from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials import Credential
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.session import session


def credential_used_to_log_in(credential: Credential, max_age: int = 60) -> bool:
    """
    Check if a particular credential was used to log in (using the eduID IdP and authn).
    """
    login_authn = session.authn.sp.get_authn_for_action(AuthnAcsAction.login)
    credential_already_used = False
    if login_authn and credential.key in login_authn.credentials_used:
        if login_authn.authn_instant is not None:
            age = (utc_now() - login_authn.authn_instant).total_seconds()
            if 0 < age < max_age:
                credential_already_used = True
    return credential_already_used
