from enum import Enum, unique

from eduid.webapp.common.api.messages import TranslatableMsg


@unique
class IdPMsg(str, TranslatableMsg):
    action_required = 'login.action_required'  # Shouldn't actually be returned to the frontend
    assurance_failure = 'login.assurance_failure'
    assurance_not_possible = 'login.assurance_not_possible'
    bad_ref = 'login.bad_ref'
    credential_expired = 'login.credential_expired'
    finished = 'login.finished'
    general_failure = 'login.general_failure'
    mfa_required = 'login.mfa_required'
    mfa_auth_failed = 'login.mfa_auth_failed'
    must_authenticate = 'login.must_authenticate'
    no_sso_session = 'login.no_sso_session'
    not_available = 'login.not_available'
    not_implemented = 'login.not_implemented'
    other_device = 'login.use_another_device'
    proceed = 'login.proceed'  # Shouldn't actually be returned to the frontend
    state_not_found = 'login.state_not_found'
    swamid_mfa_required = 'login.swamid_mfa_required'
    tou_not_acceptable = 'login.tou_not_acceptable'
    tou_required = 'login.tou_required'
    user_temporary_locked = 'login.user_temporary_locked'
    user_terminated = 'login.user_terminated'
    wrong_credentials = 'login.wrong_credentials'
    wrong_user = 'login.wrong_user'
    # copied from eidas.helpers.EidasMsg
    eidas_authn_context_mismatch = 'eidas.authn_context_mismatch'
    eidas_reauthn_expired = 'eidas.reauthn_expired'
    eidas_nin_not_matching = 'eidas.nin_not_matching'


@unique
class IdPAction(str, Enum):
    PWAUTH = 'USERNAMEPASSWORD'
    MFA = 'MFA'
    TOU = 'TOU'
    OTHER_DEVICE = 'OTHER_DEVICE'
    FINISHED = 'FINISHED'
