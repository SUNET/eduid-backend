from enum import Enum, unique

from eduid.webapp.common.api.messages import TranslatableMsg


@unique
class IdPMsg(str, TranslatableMsg):
    aborted = "login.aborted"
    unknown_device = "login.unknown_device"
    action_required = "login.action_required"  # Shouldn't actually be returned to the frontend
    assurance_failure = "login.assurance_failure"
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
class IdPAction(str, Enum):
    NEW_DEVICE = "NEW_DEVICE"
    OTHER_DEVICE = "OTHER_DEVICE"
    PWAUTH = "USERNAMEPASSWORD"
    MFA = "MFA"
    TOU = "TOU"
    FINISHED = "FINISHED"
