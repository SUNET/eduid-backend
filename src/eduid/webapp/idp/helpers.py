import logging
from enum import StrEnum, unique
from typing import Any

from saml2 import BINDING_HTTP_POST

from eduid.userdb.idp import IdPUser
from eduid.webapp.common.api.messages import FluxData, TranslatableMsg, error_response, success_response
from eduid.webapp.idp.idp_saml import SAMLResponseParams

logger = logging.getLogger(__name__)


@unique
class IdPMsg(str, TranslatableMsg):
    aborted = "login.aborted"
    unknown_device = "login.unknown_device"
    action_required = "login.action_required"  # Shouldn't actually be returned to the frontend
    assurance_failure = "login.assurance_failure"  # Shouldn't actually be returned to the frontend
    assurance_not_possible = "login.assurance_not_possible"
    bad_ref = "login.bad_ref"
    credential_expired = "login.credential_expired"
    finished = "login.finished"
    general_failure = "login.general_failure"
    mfa_required = "login.mfa_required"
    mfa_auth_failed = "login.mfa_auth_failed"
    mfa_proofing_method_not_allowed = "login.mfa_proofing_method_not_allowed"
    must_authenticate = "login.must_authenticate"
    no_sso_session = "login.no_sso_session"
    not_available = "login.not_available"
    not_implemented = "login.not_implemented"
    identity_proofing_method_not_allowed = "login.identity_proofing_method_not_allowed"
    other_device = "login.use_another_device"
    other_device_expired = "login.other_device_expired"
    proceed = "login.proceed"  # Shouldn't actually be returned to the frontend
    security_key_required = "login.security_key_required"  # used for accounts that forces security key for all logins
    state_not_found = "login.state_not_found"
    state_already_used = "login.state_already_used"
    tou_not_acceptable = "login.tou_not_acceptable"
    tou_required = "login.tou_required"
    user_temporary_locked = "login.user_temporary_locked"
    user_terminated = "login.user_terminated"
    wrong_credentials = "login.wrong_credentials"
    wrong_user = "login.wrong_user"
    # copied from eidas.helpers.EidasMsg
    eidas_authn_context_mismatch = "eidas.authn_context_mismatch"
    eidas_reauthn_expired = "eidas.reauthn_expired"
    eidas_nin_not_matching = "eidas.nin_not_matching"


@unique
class IdPAction(StrEnum):
    NEW_DEVICE = "NEW_DEVICE"
    OTHER_DEVICE = "OTHER_DEVICE"
    USERNAMEPWAUTH = "USERNAMEPASSWORD"
    PWAUTH = "PASSWORD"
    MFA = "MFA"
    TOU = "TOU"
    FINISHED = "FINISHED"


def lookup_user(username: str, managed_account_allowed: bool = False) -> IdPUser | None:
    """
    Lookup a user by username in both central userdb and in managed account db
    """
    from eduid.webapp.idp.app import current_idp_app as current_app

    # check for managed user where username always starts with ma-
    if username.startswith("ma-"):
        if not managed_account_allowed:
            return None
        return current_app.managed_account_db.get_account_as_idp_user(username)
    else:
        return current_app.userdb.lookup_user(username)


def create_saml_sp_response(saml_params: SAMLResponseParams, authn_options: dict[str, Any]) -> FluxData:
    """
    Create a response to frontend that should be posted to the SP
    """
    if saml_params.binding != BINDING_HTTP_POST:
        logger.error("SAML response does not have binding HTTP_POST")
        return error_response(message=IdPMsg.general_failure)
    return success_response(
        message=IdPMsg.finished,
        payload={
            "action": IdPAction.FINISHED.value,
            "target": saml_params.url,
            "parameters": saml_params.post_params,
            "missing_attributes": saml_params.missing_attributes,
            "authn_options": authn_options,
        },
    )
