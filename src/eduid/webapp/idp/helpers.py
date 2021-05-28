from enum import Enum, unique

from eduid.webapp.common.api.messages import TranslatableMsg


@unique
class IdPMsg(str, TranslatableMsg):
    action_required = 'idp.action_required'  # Shouldn't actually be returned to the frontend
    assurance_failure = 'idp.assurance_failure'
    assurance_not_possible = 'idp.assurance_not_possible'
    bad_ref = 'idp.bad_ref'
    credential_expired = 'idp.credential_expired'
    general_failure = 'idp.general_failure'
    mfa_required = 'idp.mfa_required'
    mfa_auth_failed = 'idp.mfa_auth_failed'
    must_authenticate = 'idp.must_authenticate'
    not_available = 'idp.not_available'
    not_implemented = 'idp.not_implemented'
    proceed = 'idp.proceed'  # Shouldn't actually be returned to the frontend
    swamid_mfa_required = 'idp.swamid_mfa_required'
    tou_not_acceptable = 'idp.tou_not_acceptable'
    tou_required = 'idp.tou_required'
    user_temporary_locked = 'idp.user_temporary_locked'
    user_terminated = 'idp.user_terminated'
    wrong_credentials = 'idp.wrong_credentials'
    wrong_user = 'idp.wrong_user'


@unique
class IdPAction(str, Enum):
    PWAUTH = 'USERNAMEPASSWORD'
    MFA = 'MFA'
    TOU = 'TOU'
    FINISHED = 'FINISHED'
