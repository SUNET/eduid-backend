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
from eduid.userdb.credentials.fido import FidoCredential
from eduid.webapp.common.api.messages import AuthnStatusMsg, TranslatableMsg
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult
from eduid.webapp.common.authn.utils import check_reauthn
from eduid.webapp.common.proofing.base import ProofingFunctions
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.common.proofing.methods import ProofingMethodSAML
from eduid.webapp.common.proofing.saml_helpers import is_required_loa, is_valid_authn_instant
from eduid.webapp.common.session.namespaces import RP_AuthnRequest, SP_AuthnRequest

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


def run_verify_credential(
    user: User,
    args: ACSArgs,
    *,
    common_saml_checks: Callable[[ACSArgs], ACSResult | None] | None,
    get_proofing_functions: Callable[..., ProofingFunctions[Any]],
    method_not_available_msg: TranslatableMsg,
    credential_not_found_msg: TranslatableMsg,
    identity_not_matching_msg: TranslatableMsg,
    credential_verify_success_msg: TranslatableMsg,
    app_name: str,
    config: object,
) -> ACSResult:
    """Shared verify-credential action logic.

    Verifies a user's FIDO credential using an external identity assertion.
    If the user doesn't have a verified identity, it is verified first.
    Uses ``proofing.get_current_loa()`` for LoA retrieval (works for both SAML and OIDC).

    Pass ``None`` for ``common_saml_checks`` when the webapp is OIDC-based.
    """
    if not args.proofing_method:
        return ACSResult(message=method_not_available_msg)

    if common_saml_checks is not None:
        if ret := common_saml_checks(args):
            return ret

    assert isinstance(args.authn_req, SP_AuthnRequest | RP_AuthnRequest)

    credential = user.credentials.find(args.authn_req.proofing_credential_id)
    if not isinstance(credential, FidoCredential):
        logger.error(f"Credential {credential} is not a FidoCredential")
        return ACSResult(message=credential_not_found_msg)

    _need_reauthn = check_reauthn(
        frontend_action=args.authn_req.frontend_action, user=user, credential_requested=credential
    )
    if _need_reauthn:
        logger.error(f"User needs to authenticate: {_need_reauthn}")
        return ACSResult(message=AuthnStatusMsg.must_authenticate)

    parsed = args.proofing_method.parse_session_info(args.session_info, args.backdoor)
    if parsed.error:
        return ACSResult(message=parsed.error)

    assert isinstance(parsed.info, BaseModel)

    proofing = get_proofing_functions(
        session_info=parsed.info, app_name=app_name, config=config, backdoor=args.backdoor
    )

    _identity = proofing.get_identity(user=user)
    if not _identity or not _identity.is_verified:
        verify_result = proofing.verify_identity(user=user)
        if verify_result.error is not None:
            return ACSResult(message=verify_result.error)
        if verify_result.user:
            user = verify_result.user
            credential = user.credentials.find(credential.key)
            if not isinstance(credential, FidoCredential):
                logger.error(f"Credential {credential} is not a FidoCredential")
                return ACSResult(message=credential_not_found_msg)

    match_res = proofing.match_identity(user=user, proofing_method=args.proofing_method)
    if match_res.error is not None:
        return ACSResult(message=match_res.error)

    if not match_res.matched:
        from flask import current_app as flask_app

        flask_app.stats.count(name=f"verify_credential_{args.proofing_method.method}_identity_not_matching")  # type: ignore[attr-defined]
        return ACSResult(message=identity_not_matching_msg)

    current_loa = proofing.get_current_loa()
    if current_loa.error is not None:
        return ACSResult(message=current_loa.error)

    verify_result = proofing.verify_credential(user=user, credential=credential, loa=current_loa.result)
    if verify_result.error is not None:
        return ACSResult(message=verify_result.error)

    from flask import current_app as flask_app

    flask_app.stats.count(name="fido_token_verified")  # type: ignore[attr-defined]
    flask_app.stats.count(name=f"verify_credential_{args.proofing_method.method}_success")  # type: ignore[attr-defined]

    return ACSResult(success=True, message=credential_verify_success_msg)


def run_mfa_authenticate(
    args: ACSArgs,
    *,
    common_saml_checks: Callable[[ACSArgs], ACSResult | None] | None,
    get_proofing_functions: Callable[..., ProofingFunctions[Any]],
    get_user: Callable[[], Any],
    method_not_available_msg: TranslatableMsg,
    identity_not_matching_msg: TranslatableMsg,
    mfa_authn_success_msg: TranslatableMsg,
    app_name: str,
    config: object,
) -> ACSResult:
    """Shared MFA authentication action logic.

    Emits ``mfa_auth_success`` and ``mfa_auth_{method}_success`` stats on success.
    The issuer-specific stat (``mfa_auth_{issuer}_success``) must be emitted by the
    caller since the issuer source is protocol-specific (SAML issuer vs OIDC static).

    :param get_user: Callable returning the user (typically from session.mfa_action.eppn).
    """
    if not args.proofing_method:
        return ACSResult(message=method_not_available_msg)

    if common_saml_checks is not None:
        if ret := common_saml_checks(args):
            return ret

    user = get_user()

    parsed = args.proofing_method.parse_session_info(args.session_info, backdoor=args.backdoor)
    if parsed.error:
        return ACSResult(message=parsed.error)

    assert isinstance(parsed.info, BaseModel)

    proofing = get_proofing_functions(
        session_info=parsed.info, app_name=app_name, config=config, backdoor=args.backdoor
    )

    match_res = proofing.match_identity(user=user, proofing_method=args.proofing_method)
    logger.debug(f"MFA authentication identity matching result: {match_res}")
    if match_res.error is not None:
        return ACSResult(message=match_res.error)

    if not match_res.matched:
        from flask import current_app as flask_app

        flask_app.stats.count(name=f"mfa_auth_{args.proofing_method.method}_identity_not_matching")  # type: ignore[attr-defined]
        return ACSResult(message=identity_not_matching_msg)

    from flask import current_app as flask_app

    flask_app.stats.count(name="mfa_auth_success")  # type: ignore[attr-defined]
    flask_app.stats.count(name=f"mfa_auth_{args.proofing_method.method}_success")  # type: ignore[attr-defined]
    return ACSResult(success=True, message=mfa_authn_success_msg)
