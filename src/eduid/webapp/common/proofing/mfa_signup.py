"""
Shared scaffolding for `mfa_register` ACS handlers in external MFA webapps
(eidas, bankid, samleid, freja_eid).

Each webapp's handler handles identity-field extraction for its own session-info
subclasses; this helper handles the validation boilerplate that every handler needs.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from eduid.userdb.credentials.external import TrustFramework
from eduid.webapp.bankid.saml_session_info import BankIDSessionInfo
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult
from eduid.webapp.common.proofing.base import ProofingFunctions
from eduid.webapp.eidas.saml_session_info import ForeignEidSessionInfo, NinSessionInfo
from eduid.webapp.freja_eid.helpers import FrejaEIDDocumentUserInfo
from eduid.webapp.svipe_id.helpers import SvipeDocumentUserInfo

logger = logging.getLogger(__name__)


@dataclass
class MfaRegisterParsed:
    session_info: (
        NinSessionInfo | ForeignEidSessionInfo | BankIDSessionInfo | FrejaEIDDocumentUserInfo | SvipeDocumentUserInfo
    )
    framework: TrustFramework
    loa: str


def parse_mfa_register_args(
    args: ACSArgs,
    *,
    common_saml_checks: Callable[[ACSArgs], ACSResult | None] | None,
    get_proofing_functions: Callable[..., ProofingFunctions[Any]],
    method_not_available_msg: TranslatableMsg,
    app: EduIDBaseApp,
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
        logger.error("No proofing method specified.")
        return ACSResult(message=method_not_available_msg)

    if common_saml_checks is not None:
        if ret := common_saml_checks(args):
            return ret

    parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
    if parsed.error:
        logger.error(f"Parsing error for {args.proofing_method.method}: {parsed.error}")
        return ACSResult(message=parsed.error)

    if parsed.info is None:
        logger.error("No session info.")
        return ACSResult(message=method_not_available_msg)

    proofing = get_proofing_functions(
        session_info=parsed.info,
        app_name=app.name,
        config=app.conf,
        backdoor=args.backdoor,
    )
    current_loa = proofing.get_current_loa()
    if current_loa.error is not None:
        logger.error(f"Proofing error for {args.proofing_method.method}: {current_loa.error}")
        return ACSResult(message=current_loa.error)
    if not current_loa.result:
        logger.error(f"No LOA result for {args.proofing_method.method}.")
        return ACSResult(message=method_not_available_msg)

    return MfaRegisterParsed(
        session_info=parsed.info,
        framework=args.proofing_method.framework,
        loa=current_loa.result,
    )
