"""
Shared action helpers for external identity proofing ACS/callback handlers.

Each webapp's action function becomes a thin wrapper that delegates to these helpers,
passing in app-specific callables and message constants.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from eduid.userdb import User
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult
from eduid.webapp.common.proofing.base import ProofingFunctions
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.common.proofing.methods import ProofingMethodSAML
from eduid.webapp.common.proofing.saml_helpers import is_required_loa, is_valid_authn_instant

logger = logging.getLogger(__name__)


def run_common_saml_checks(
    args: ACSArgs,
    *,
    authn_context_mismatch_msg: TranslatableMsg,
    authn_instant_too_old_msg: TranslatableMsg,
    loa_authn_context_map: dict[str, str],
) -> ACSResult | None:
    """Shared SAML validation: LoA check and authn instant freshness.

    :param args: ACS action arguments
    :param authn_context_mismatch_msg: App-specific error message for LoA mismatch
    :param authn_instant_too_old_msg: App-specific error message for stale authn
    :param loa_authn_context_map: Config mapping LoA names to authn context URIs
    :returns: ACSResult with error if validation fails, None on success
    """
    assert isinstance(args.proofing_method, ProofingMethodSAML)  # please mypy
    if not is_required_loa(args.session_info, args.proofing_method.required_loa, loa_authn_context_map):
        logger.error("SAML response did not meet required LOA")
        args.authn_req.error = True
        args.authn_req.status = authn_context_mismatch_msg.value
        return ACSResult(message=authn_context_mismatch_msg)

    if not is_valid_authn_instant(args.session_info):
        logger.error("SAML response was not a valid reauthn")
        args.authn_req.error = True
        args.authn_req.status = authn_instant_too_old_msg.value
        return ACSResult(message=authn_instant_too_old_msg)

    return None


def run_verify_identity(
    user: User,
    args: ACSArgs,
    *,
    common_saml_checks: Callable[[ACSArgs], ACSResult | None] | None,
    get_proofing_functions: Callable[..., ProofingFunctions[Any]],
    method_not_available_msg: TranslatableMsg,
    identity_verify_success_msg: TranslatableMsg,
    app_name: str,
    config: object,
) -> ACSResult:
    """Shared verify-identity action logic.

    Pass ``None`` for ``common_saml_checks`` when the webapp is OIDC-based.
    """
    if not args.proofing_method:
        return ACSResult(message=method_not_available_msg)

    if common_saml_checks is not None:
        if ret := common_saml_checks(args):
            return ret

    parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
    if parsed.error:
        return ACSResult(message=parsed.error)

    assert isinstance(parsed.info, BaseModel)

    proofing = get_proofing_functions(
        session_info=parsed.info, app_name=app_name, config=config, backdoor=args.backdoor
    )

    current = proofing.get_identity(user)
    if current and current.is_verified:
        logger.error(f"User already has a verified identity for {args.proofing_method.method}")
        logger.debug(f"Current: {current}. Assertion: {args.session_info}")
        return ACSResult(message=ProofingMsg.identity_already_verified)

    verify_result = proofing.verify_identity(user=user)
    if verify_result.error is not None:
        return ACSResult(message=verify_result.error)

    return ACSResult(success=True, message=identity_verify_success_msg)
