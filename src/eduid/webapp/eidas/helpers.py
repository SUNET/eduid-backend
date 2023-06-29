import logging
from dataclasses import dataclass
from enum import unique
from typing import Any, Optional

from flask import abort, make_response, request, url_for
from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.metadata import entity_descriptor
from saml2.request import AuthnRequest
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.misc.timeutil import utc_now
from eduid.common.utils import urlappend
from eduid.userdb import User
from eduid.userdb.credentials import FidoCredential
from eduid.userdb.credentials.external import TrustFramework
from eduid.webapp.authn.helpers import credential_used_to_authenticate
from eduid.webapp.common.api.errors import EduidErrorsContext, goto_errors_response
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.authn.cache import OutstandingQueriesCache
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import AuthnRequestRef
from eduid.webapp.eidas.app import current_eidas_app as current_app
from eduid.webapp.eidas.saml_session_info import BaseSessionInfo

__author__ = "lundberg"

logger = logging.getLogger(__name__)


@unique
class EidasMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # LOA 3 not needed
    authn_context_mismatch = "eidas.authn_context_mismatch"
    # re-authentication expired
    reauthn_expired = "eidas.reauthn_expired"  # TODO: Use must_authenticate instead
    # the token was not used to authenticate this session
    token_not_in_creds = "eidas.token_not_in_credentials_used"  # TODO: Use must_authenticate instead
    # the personalIdentityNumber from Sweden Connect does not correspond
    # to a verified nin in the user's account, or prid does not correspond to the verified EIDAS identity
    identity_not_matching = "eidas.identity_not_matching"
    # The user already has a verified NIN
    nin_already_verified = "eidas.nin_already_verified"  # TODO: Use identity_already_verified instead
    # The user already has a verified NIN/EIDAS identity
    identity_already_verified = "eidas.identity_already_verified"
    # Successfully verified the NIN/EIDAS identity
    identity_verify_success = "eidas.identity_verify_success"
    # missing redirect URL for mfa authn
    no_redirect_url = "eidas.no_redirect_url"
    # Token not found on the credentials in the user's account
    token_not_found = "eidas.token_not_found"
    # Attribute missing from IdP
    attribute_missing = "eidas.attribute_missing"
    # Unavailable vetting method requested
    method_not_available = "eidas.method_not_available"
    # Need to authenticate (again?) before performing this action
    must_authenticate = "eidas.must_authenticate"
    # Status requested for unknown authn_id
    not_found = "eidas.not_found"
    # Action completed, redirect to actions app
    action_completed = "actions.action-completed"
    # Successfully authenticated with external MFA
    mfa_authn_success = "eidas.mfa_authn_success"
    # Successfully verified a credential
    credential_verify_success = "eidas.credential_verify_success"

    old_token_verify_success = "eidas.token_verify_success"
    old_nin_verify_success = "eidas.nin_verify_success"


def create_authn_request(
    authn_ref: AuthnRequestRef,
    framework: TrustFramework,
    selected_idp: str,
    required_loa: list[str],
    force_authn: bool = False,
) -> AuthnRequest:
    if framework not in [TrustFramework.SWECONN, TrustFramework.EIDAS]:
        raise ValueError(f"Unrecognised trust framework: {framework}")

    kwargs: dict[str, Any] = {
        "force_authn": str(force_authn).lower(),
    }

    # LOA
    logger.debug(f"Requesting AuthnContext {required_loa}")
    loa_uris = [current_app.conf.authentication_context_map[loa] for loa in required_loa]
    kwargs["requested_authn_context"] = {"authn_context_class_ref": loa_uris, "comparison": "exact"}

    client = Saml2Client(current_app.saml2_config)
    try:
        session_id, info = client.prepare_for_authenticate(
            entityid=selected_idp,
            relay_state=authn_ref,
            binding=BINDING_HTTP_REDIRECT,
            sigalg=current_app.conf.authn_sign_alg,
            digest_alg=current_app.conf.authn_digest_alg,
            **kwargs,
        )
    except TypeError:
        logger.error("Unable to know which IdP to use")
        raise

    oq_cache = OutstandingQueriesCache(session.eidas.sp.pysaml2_dicts)
    oq_cache.set(session_id, authn_ref)
    return info


def is_required_loa(session_info: SessionInfo, required_loa: list[str]) -> bool:
    parsed_session_info = BaseSessionInfo(**session_info)
    if not required_loa:
        logger.debug(f"No LOA required, allowing {parsed_session_info.authn_context}")
        return True
    loa_uris = [current_app.conf.authentication_context_map.get(loa) for loa in required_loa]
    if not loa_uris:
        logger.error(f"LOA {required_loa} not found in configuration (authentication_context_map), disallowing")
        return False
    if parsed_session_info.authn_context in loa_uris:
        logger.debug(f"Asserted authn context {parsed_session_info.authn_context} matches required {required_loa}")
        return True
    logger.error("Asserted authn context class does not match required class")
    logger.error(f"Asserted: {parsed_session_info.authn_context}")
    logger.error(f"Required: {loa_uris} ({required_loa})")
    return False


def authn_ctx_to_loa(session_info: SessionInfo) -> Optional[str]:
    """Lookup short name (such as 'loa3') for an authentication context class we've received."""
    parsed = BaseSessionInfo(**session_info)
    for k, v in current_app.conf.authentication_context_map.items():
        if v == parsed.authn_context:
            return k
    return None


def authn_context_class_to_loa(session_info: BaseSessionInfo) -> Optional[str]:
    for key, value in current_app.conf.authentication_context_map.items():
        if value == session_info.authn_context:
            return key
    return None


def is_valid_reauthn(session_info: SessionInfo, max_age: int = 60) -> bool:
    """
    :param session_info: The SAML2 session_info
    :param max_age: Max time (in seconds) since authn that is to be allowed
    :return: True if authn instant is no older than max_age
    """
    parsed_session_info = BaseSessionInfo(**session_info)
    now = utc_now()
    age = now - parsed_session_info.authn_instant
    if age.total_seconds() <= max_age:
        logger.debug(
            f"Re-authn is valid, authn instant {parsed_session_info.authn_instant}, age {age}, max_age {max_age}s"
        )
        return True
    logger.error(f"Authn instant {parsed_session_info.authn_instant} too old (age {age}, max_age {max_age} seconds)")
    return False


def create_metadata(config):
    return entity_descriptor(config)


def attribute_remap(session_info: SessionInfo) -> SessionInfo:
    """
    Remap from known test attributes to users correct attributes.

    :param session_info: the SAML session info
    :return: SAML session info with new nin mapped
    """
    personal_identity_number = session_info.get("ava", {}).get("personalIdentityNumber")
    if personal_identity_number:
        asserted_test_nin = personal_identity_number[0]
        user_nin = current_app.conf.nin_attribute_map.get(asserted_test_nin, None)
        if user_nin:
            session_info["ava"]["personalIdentityNumber"] = [user_nin]
    return session_info


@dataclass()
class CredentialVerifyResult:
    verified_ok: bool
    message: Optional[EidasMsg] = None
    response: Optional[WerkzeugResponse] = None  # TODO: make obsolete and remove
    location: Optional[str] = None


def check_credential_to_verify(user: User, credential_id: str) -> CredentialVerifyResult:
    # Check if requested key id is a mfa token and if the user used that to log in
    token_to_verify = user.credentials.find(credential_id)
    if not isinstance(token_to_verify, FidoCredential):
        current_app.logger.error(f"Credential {token_to_verify} is not a FidoCredential")
        # return redirect_with_msg(redirect_url, EidasMsg.token_not_found)
        return CredentialVerifyResult(verified_ok=False, message=EidasMsg.token_not_found)

    # Check if the credential was just now (within 60s) used to log in
    credential_already_used = credential_used_to_authenticate(token_to_verify, max_age=60)
    current_app.logger.debug(f"Credential {credential_id} recently used for login: {credential_already_used}")
    if not credential_already_used:
        # If token was not used for login, ask authn to authenticate the user again,
        # and then return to this endpoint with the same credential_id. Better luck next time I guess.
        current_app.logger.info(f"Started proofing of token {token_to_verify.key}, redirecting to authn")
        reauthn_url = urlappend(current_app.conf.token_service_url, "reauthn")
        next_url = url_for("old_eidas.verify_token", credential_id=token_to_verify.key, _external=True)
        # Add idp arg to next_url if set
        idp = request.args.get("idp")
        if idp and idp not in current_app.saml2_config.metadata.identity_providers():
            if not current_app.conf.errors_url_template:
                abort(make_response("Requested IdP not found in metadata", 404))
            _response = goto_errors_response(
                errors_url=current_app.conf.errors_url_template,
                ctx=EduidErrorsContext.SAML_REQUEST_MISSING_IDP,
                rp=current_app.saml2_config.entityid,
            )
            return CredentialVerifyResult(verified_ok=False, response=_response, message=EidasMsg.method_not_available)

        if idp:
            next_url = f"{next_url}?idp={idp}"
        redirect_url = f"{reauthn_url}?next={next_url}"
        current_app.logger.debug(f"Redirecting user to {redirect_url} for re-authentication")
        return CredentialVerifyResult(verified_ok=False, location=redirect_url, message=EidasMsg.must_authenticate)

    return CredentialVerifyResult(verified_ok=True)
