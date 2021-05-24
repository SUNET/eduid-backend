from enum import Enum, unique

from eduid.webapp.common.api.messages import TranslatableMsg


@unique
class IdPMsg(str, TranslatableMsg):
    user_terminated = 'idp.user_terminated'
    must_authenticate = 'idp.must_authenticate'
    swamid_mfa_required = 'idp.swamid_mfa_required'
    mfa_required = 'idp.mfa_required'
    assurance_not_possible = 'idp.assurance_not_possible'
    assurance_failure = 'idp.assurance_failure'
    action_required = 'idp.action_required'  # Shouldn't actually be returned to the frontend
    proceed = 'idp.proceed'  # Shouldn't actually be returned to the frontend
    wrong_user = 'idp.wrong_user'
    not_implemented = 'idp.not_implemented'
    bad_ref = 'idp.bad_ref'
    wrong_credentials = 'idp.wrong_credentials'
    user_temporary_locked = 'idp.user_temporary_locked'
    credential_expired = 'idp.credential_expired'


@unique
class IdPAction(str, Enum):
    PWAUTH = 'USERNAMEPASSWORD'
    MFA = 'MFA'
    FINISHED = 'FINISHED'
