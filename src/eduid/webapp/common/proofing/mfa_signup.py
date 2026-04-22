"""
Shared scaffolding for `mfa_register` ACS handlers in external MFA webapps
(eidas, bankid, samleid, freja_eid).

Each webapp's handler handles identity-field extraction for its own session-info
subclasses; this helper handles the validation boilerplate that every handler needs.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from eduid.userdb.credentials.external import TrustFramework
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult
from eduid.webapp.common.proofing.base import ProofingFunctions


@dataclass
class MfaRegisterParsed:
    # Concrete type is one of: NinSessionInfo, ForeignEidSessionInfo, BankIDSessionInfo (SAML-based),
    # or FrejaEIDDocumentUserInfo, SvipeDocumentUserInfo (OIDC-based). All are Pydantic BaseModel subclasses.
    session_info: BaseModel
    framework: TrustFramework
    loa: str


def parse_mfa_register_args(
    args: ACSArgs,
    *,
    common_saml_checks: Callable[[ACSArgs], ACSResult | None] | None,
    get_proofing_functions: Callable[..., ProofingFunctions[Any]],
    method_not_available_msg: TranslatableMsg,
    app_name: str,
    config: object,
) -> MfaRegisterParsed | ACSResult:
    """Run the common validation pipeline for a signup-flow external MFA ACS callback.

    On success returns a :class:`MfaRegisterParsed` with the parsed session info,
    proofing framework (from the proofing method) and current LoA.

    On failure returns an :class:`ACSResult` with the appropriate error message;
    the caller should propagate it unchanged.

    Pass ``None`` for ``common_saml_checks`` when the webapp is OIDC-based
    (no SAML-level checks to run).
    """
    if not args.proofing_method:
        return ACSResult(message=method_not_available_msg)

    if common_saml_checks is not None:
        if ret := common_saml_checks(args):
            return ret

    parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
    if parsed.error:
        return ACSResult(message=parsed.error)

    # After error check, parsed.info is a concrete session-info instance (a Pydantic BaseModel subclass).
    # The SessionInfoParseResult union is wide (includes None), so we narrow here to satisfy mypy.
    assert isinstance(parsed.info, BaseModel)

    proofing = get_proofing_functions(
        session_info=parsed.info,
        app_name=app_name,
        config=config,
        backdoor=args.backdoor,
    )
    current_loa = proofing.get_current_loa()
    if current_loa.error is not None:
        return ACSResult(message=current_loa.error)

    return MfaRegisterParsed(
        session_info=parsed.info,
        framework=args.proofing_method.framework,
        loa=current_loa.result or "",
    )
