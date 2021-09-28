from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials import Credential
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.session import session


def credential_used_to_authenticate(credential: Credential, max_age: int) -> bool:
    """
    Check if a particular credential was used to authenticate (using the eduID IdP and authn).
    """
    current_action = None
    login_action = session.authn.sp.get_authn_for_action(AuthnAcsAction.login)
    reauthn_actions = session.authn.sp.get_authn_for_action(AuthnAcsAction.reauthn)
    if login_action and credential.key in login_action.credentials_used:
        current_action = login_action
    elif reauthn_actions and credential.key in reauthn_actions.credentials_used:
        current_action = reauthn_actions

    if current_action and credential.key in current_action.credentials_used:
        if current_action.authn_instant is not None:
            age = (utc_now() - current_action.authn_instant).total_seconds()
            if 0 < age < max_age:
                return True
    return False
