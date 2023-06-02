from enum import unique
import logging
from typing import Optional

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials import Credential
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import SP_AuthnRequest

logger = logging.getLogger(__name__)


def credential_used_to_authenticate(credential: Credential, max_age: int) -> bool:
    """
    Check if a particular credential was used to authenticate (using the eduID IdP and authn).
    """
    logger.debug(f"Checking if credential {credential} has been used in the last {max_age} seconds")

    login = session.authn.sp.get_authn_for_action(AuthnAcsAction.login)
    reauthn = session.authn.sp.get_authn_for_action(AuthnAcsAction.reauthn)

    if _credential_recently_used(credential, login, max_age) or _credential_recently_used(credential, reauthn, max_age):
        return True
    return False


def _credential_recently_used(credential: Credential, action: Optional[SP_AuthnRequest], max_age: int) -> bool:
    if action and credential.key in action.credentials_used:
        if action.authn_instant is not None:
            age = (utc_now() - action.authn_instant).total_seconds()
            if 0 < age < max_age:
                return True
    return False


@unique
class AuthnMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # Status requested for unknown authn_id
    not_found = "authn.not_found"
