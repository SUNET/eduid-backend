from enum import unique

from eduid.webapp.common.api.messages import TranslatableMsg


@unique
class AuthnMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    frontend_action_not_supported = "authn.frontend_action_not_supported"
