from enum import Enum, unique

from eduid.webapp.common.api.messages import TranslatableMsg


@unique
class IdPMsg(str, TranslatableMsg):
    action_required = 'login.action_required'  # Shouldn't actually be returned to the frontend
    assurance_failure = 'login.assurance_failure'
    assurance_not_possible = 'login.assurance_not_possible'
    bad_ref = 'login.bad_ref'
    credential_expired = 'login.credential_expired'
    general_failure = 'login.general_failure'
    mfa_required = 'login.mfa_required'
    mfa_auth_failed = 'login.mfa_auth_failed'
    must_authenticate = 'login.must_authenticate'
    not_available = 'login.not_available'
    not_implemented = 'login.not_implemented'
    proceed = 'login.proceed'  # Shouldn't actually be returned to the frontend
    swamid_mfa_required = 'login.swamid_mfa_required'
    tou_not_acceptable = 'login.tou_not_acceptable'
    tou_required = 'login.tou_required'
    user_temporary_locked = 'login.user_temporary_locked'
    user_terminated = 'login.user_terminated'
    wrong_credentials = 'login.wrong_credentials'
    wrong_user = 'login.wrong_user'


@unique
class IdPAction(str, Enum):
    PWAUTH = 'USERNAMEPASSWORD'
    MFA = 'MFA'
    TOU = 'TOU'
    FINISHED = 'FINISHED'
