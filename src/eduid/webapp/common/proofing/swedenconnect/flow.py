"""
Shared identity verification flow for Sweden Connect webapps (samleid, and OIDC siblings).

The ACS/callback action bodies and the parts of the views that do not depend on how the IdP response was
obtained live here. Protocol specifics (assertion or token validation, authn request creation, session namespace
access) stay in the webapps and are passed in as callables or explicit values.

Not everything here is transport neutral: the helpers use Flask (redirect, FluxData), and remap_staging_nin expects
the SAML style SessionInfo shape ({"ava": {"personalIdentityNumber": [...]}}), which an OIDC webapp must produce
(and is a silent no-op for any other shape). build_status_payload and apply_action_result accept the authn request
types of both transports.
"""

import logging
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from flask import redirect
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.config.base import EduidEnvironment, FrontendAction
from eduid.userdb import User
from eduid.userdb.credentials import FidoCredential
from eduid.userdb.element import ElementKey
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.messages import CommonMsg, FluxData, TranslatableMsg, error_response
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.authn.utils import check_reauthn
from eduid.webapp.common.proofing.app import ProofingApp
from eduid.webapp.common.proofing.mfa_signup import parse_mfa_register_args
from eduid.webapp.common.proofing.shared_actions import (
    run_mfa_authenticate,
    run_verify_credential,
    run_verify_identity,
)
from eduid.webapp.common.proofing.swedenconnect.proofing import get_swedenconnect_proofing_functions
from eduid.webapp.common.proofing.swedenconnect.session_info import (
    BankIDSessionInfo,
    ForeignEidSessionInfo,
    NinSessionInfo,
)
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import (
    AuthnRequestRef,
    ExternalMfaSignupBankIDIdentity,
    ExternalMfaSignupEIDASIdentity,
    ExternalMfaSignupSwedenConnectIdentity,
    RP_AuthnRequest,
    SP_AuthnRequest,
)

__author__ = "lundberg"

logger = logging.getLogger(__name__)

# Required (never None) for every Sweden Connect webapp, SAML or OIDC: these are the assurance level and authn instant
# checks. Passing None to the underlying shared_actions functions would skip them.
type CommonChecks = Callable[[ACSArgs], ACSResult | None]


@dataclass(frozen=True)
class SwedenConnectMsgs:
    """The app-specific messages the shared Sweden Connect flow needs."""

    authn_context_mismatch: TranslatableMsg
    authn_instant_too_old: TranslatableMsg
    method_not_available: TranslatableMsg
    identity_verify_success: TranslatableMsg
    credential_not_found: TranslatableMsg
    identity_not_matching: TranslatableMsg
    credential_verify_success: TranslatableMsg
    mfa_authn_success: TranslatableMsg
    frontend_action_not_supported: TranslatableMsg
    credential_verification_not_allowed: TranslatableMsg


# ---------------------------------------------------------------------------
# ACS/callback action bodies
# ---------------------------------------------------------------------------


def sc_verify_identity(
    user: User, args: ACSArgs, msgs: SwedenConnectMsgs, *, common_checks: CommonChecks, app: EduIDBaseApp
) -> ACSResult:
    """Use an IdP response to verify a user's identity (Freja eID, BankID or eIDAS)."""
    return run_verify_identity(
        user,
        args,
        common_saml_checks=common_checks,
        get_proofing_functions=get_swedenconnect_proofing_functions,
        method_not_available_msg=msgs.method_not_available,
        identity_verify_success_msg=msgs.identity_verify_success,
        app=app,
    )


def sc_verify_credential(
    user: User, args: ACSArgs, msgs: SwedenConnectMsgs, *, common_checks: CommonChecks, app: EduIDBaseApp
) -> ACSResult:
    """Use an IdP response to person-proof a user's FIDO credential."""
    return run_verify_credential(
        user,
        args,
        common_saml_checks=common_checks,
        get_proofing_functions=get_swedenconnect_proofing_functions,
        method_not_available_msg=msgs.method_not_available,
        credential_not_found_msg=msgs.credential_not_found,
        identity_not_matching_msg=msgs.identity_not_matching,
        credential_verify_success_msg=msgs.credential_verify_success,
        app=app,
    )


def sc_mfa_authenticate(
    args: ACSArgs,
    msgs: SwedenConnectMsgs,
    *,
    common_checks: CommonChecks,
    get_user: Callable[[], User],
    app: EduIDBaseApp,
) -> ACSResult:
    """Authenticate a user with an IdP response for multi-factor authentication."""
    return run_mfa_authenticate(
        args,
        common_saml_checks=common_checks,
        get_proofing_functions=get_swedenconnect_proofing_functions,
        get_user=get_user,
        method_not_available_msg=msgs.method_not_available,
        identity_not_matching_msg=msgs.identity_not_matching,
        mfa_authn_success_msg=msgs.mfa_authn_success,
        app=app,
    )


def sc_mfa_register(
    args: ACSArgs, msgs: SwedenConnectMsgs, *, common_checks: CommonChecks, app: EduIDBaseApp
) -> ACSResult:
    """Parse a signup-flow external MFA response and persist identity + LoA on the authn request."""
    parsed = parse_mfa_register_args(
        args,
        common_saml_checks=common_checks,
        get_proofing_functions=get_swedenconnect_proofing_functions,
        method_not_available_msg=msgs.method_not_available,
        app=app,
    )
    if isinstance(parsed, ACSResult):
        return parsed

    match parsed.session_info:
        case NinSessionInfo():
            if parsed.session_info.authn_context is None:
                app.logger.debug(f"{parsed.session_info=}")
                raise RuntimeError("No authn context found for NinSessionInfo")
            args.authn_req.external_mfa_signup_identity = ExternalMfaSignupSwedenConnectIdentity(
                authn_context_class=parsed.session_info.authn_context,
                framework=parsed.framework,
                given_name=parsed.session_info.attributes.given_name,
                issuer=parsed.session_info.issuer,
                loa=parsed.loa,
                nin=parsed.session_info.attributes.nin,
                surname=parsed.session_info.attributes.surname,
            )
        case ForeignEidSessionInfo():
            if parsed.session_info.authn_context is None:
                app.logger.debug(f"{parsed.session_info=}")
                raise RuntimeError("No authn context found for ForeignEidSessionInfo")
            args.authn_req.external_mfa_signup_identity = ExternalMfaSignupEIDASIdentity(
                authn_context_class=parsed.session_info.authn_context,
                country_code=parsed.session_info.attributes.country_code,
                date_of_birth=datetime.combine(
                    parsed.session_info.attributes.date_of_birth, datetime.min.time(), tzinfo=UTC
                ),
                eidas_person_identifier=parsed.session_info.attributes.eidas_person_identifier,
                prid=parsed.session_info.attributes.prid,
                prid_persistence=parsed.session_info.attributes.prid_persistence,
                framework=parsed.framework,
                given_name=parsed.session_info.attributes.given_name,
                issuer=parsed.session_info.issuer,
                loa=parsed.loa,
                surname=parsed.session_info.attributes.surname,
                transaction_id=parsed.session_info.attributes.transaction_identifier,
            )
        case BankIDSessionInfo():
            args.authn_req.external_mfa_signup_identity = ExternalMfaSignupBankIDIdentity(
                given_name=parsed.session_info.attributes.given_name,
                surname=parsed.session_info.attributes.surname,
                nin=parsed.session_info.attributes.nin,
                transaction_id=parsed.session_info.attributes.transaction_id,
                framework=parsed.framework,
                loa=parsed.loa,
                issuer=parsed.session_info.issuer,
            )
        case _:
            app.logger.error(f"Unsupported session info type: {type(parsed.session_info)}")
            return ACSResult(message=msgs.method_not_available)

    return ACSResult(success=True, message=msgs.mfa_authn_success)


# ---------------------------------------------------------------------------
# View helpers
# ---------------------------------------------------------------------------


def remap_staging_nin(
    session_info: SessionInfo, *, environment: EduidEnvironment, nin_attribute_map: Mapping[str, str]
) -> SessionInfo:
    """
    Remap NIN attributes in staging/dev environments for testing purposes. No-op elsewhere.

    :param session_info: session info containing user attributes
    :param environment: current eduID environment
    :param nin_attribute_map: asserted test NIN -> NIN to use
    :returns: session info, with remapped NIN if applicable
    """
    if environment not in [EduidEnvironment.staging, EduidEnvironment.dev]:
        return session_info
    personal_identity_number = session_info.get("ava", {}).get("personalIdentityNumber")
    if personal_identity_number:
        asserted_test_nin = personal_identity_number[0]
        user_nin = nin_attribute_map.get(asserted_test_nin, None)
        if user_nin:
            session_info["ava"]["personalIdentityNumber"] = [user_nin]
    return session_info


def select_magic_cookie_idp(
    method: str, *, freja_idp: str | None, bankid_idp: str | None, eidas_idp: str | None
) -> str | None:
    """
    Pick the test IdP to use when the magic cookie is present.

    :returns: the IdP for the method, or None if magic cookie is not supported for the method
    """
    if method == "freja" and freja_idp:
        return freja_idp
    if method == "bankid" and bankid_idp:
        return bankid_idp
    if method == "eidas" and eidas_idp:
        return eidas_idp
    return None


def reset_mfa_action_for_login(authn_id: AuthnRequestRef) -> None:
    """
    Wipe the shared (common namespace) session.mfa_action before an external MFA login redirect.

    Only login_ref and eppn are carried over on purpose. The IdP (idp/views/mfa_auth.py) completes a login from
    success, credential_used, issuer, authn_instant, authn_context and webauthn_state, which are written after a
    proofing (common/proofing/base.py), so anything left over from an earlier proofing in this browser session
    could be replayed against a newly minted login_ref. Do not retain those fields.

    The new authn request ref is remembered in authn_req_ref so that the IdP can verify that the login_ref matches
    when processing a successful response. Ideally several external MFA requests could be ongoing at the same
    time, but for now only the latest one is remembered.
    """
    saved_mfa_action = deepcopy(session.mfa_action)
    del session.mfa_action
    session.mfa_action.login_ref = saved_mfa_action.login_ref
    session.mfa_action.eppn = saved_mfa_action.eppn
    session.mfa_action.authn_req_ref = authn_id


VERIFY_CREDENTIAL_ACTION = FrontendAction.VERIFY_CREDENTIAL


def check_verify_credential_request(
    user: User,
    method: str,
    credential_id: ElementKey,
    frontend_action: str,
    msgs: SwedenConnectMsgs,
    *,
    allow_eidas_credential_verification: bool,
    app: ProofingApp,
) -> FluxData | None:
    """
    Pre-checks for a verify-credential request. The request is only valid for VERIFY_CREDENTIAL_ACTION.

    :returns: an error FluxData if the request is not allowed, None if the flow can proceed
    """
    if method == "eidas" and allow_eidas_credential_verification is False:
        app.logger.error("Credential verification is not allowed for eidas")
        return error_response(message=msgs.credential_verification_not_allowed)

    _frontend_action = VERIFY_CREDENTIAL_ACTION
    if frontend_action != _frontend_action.value:
        app.logger.error(f"Invalid frontend_action: {frontend_action}")
        return error_response(message=msgs.frontend_action_not_supported)

    # verify that the user has the credential and that it was used for login recently
    credential = user.credentials.find(credential_id)
    if credential is None or isinstance(credential, FidoCredential) is False:
        app.logger.error(f"Can't find credential with id: {credential_id}")
        return error_response(message=msgs.credential_not_found)

    return check_reauthn(frontend_action=_frontend_action, user=user, credential_requested=credential)


def build_status_payload(authn_id: AuthnRequestRef, authn: SP_AuthnRequest | RP_AuthnRequest) -> dict[str, Any]:
    """Build the /get-status payload for an authn request."""
    payload: dict[str, Any] = {
        "authn_id": authn_id,
        "frontend_action": authn.frontend_action.value,
        "frontend_state": authn.frontend_state,
        "method": authn.method,
        "error": bool(authn.error),
    }
    if authn.status is not None:
        payload["status"] = authn.status
    return payload


def apply_action_result(
    result: ACSResult,
    authn_req: SP_AuthnRequest | RP_AuthnRequest,
    formatted_finish_url: str | None,
    *,
    app: ProofingApp,
) -> WerkzeugResponse:
    """
    Record an ACS/callback action result on the authn request (for /get-status) and redirect to finish_url.

    :raises RuntimeError: if formatted_finish_url is None
    """
    if formatted_finish_url is None:
        raise RuntimeError("formatted_finish_url is None — finish_url config likely empty")

    if not result.success:
        app.logger.info(f"ACS action failed: {result.message}")
        # update session so this error can be retrieved from the /status endpoint
        _msg = result.message or CommonMsg.temp_problem
        authn_req.status = _msg.value
        authn_req.error = True
        authn_req.consumed = True
        return redirect(formatted_finish_url)

    app.logger.debug(f"ACS action successful (frontend_action {authn_req.frontend_action})")
    if result.message:
        authn_req.status = result.message.value
    authn_req.error = False
    if authn_req.frontend_action != FrontendAction.SIGNUP_EXTERNAL_MFA:
        authn_req.consumed = True
    return redirect(formatted_finish_url)
