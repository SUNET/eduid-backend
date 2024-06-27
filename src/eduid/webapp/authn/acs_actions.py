from saml2.ident import code

from eduid.userdb import User
from eduid.webapp.authn.app import current_authn_app as current_app
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, acs_action
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import LoginApplication


def update_user_session(session_info: SessionInfo, user: User) -> None:
    """
    Store login info in the session

    :param session_info: the SAML session info
    :param user: the authenticated user

    :return: None
    """
    session.authn.name_id = code(session_info["name_id"])
    if session.common.eppn and session.common.eppn != user.eppn:
        current_app.logger.warning(f"Refusing to change eppn in session from {session.common.eppn} to {user.eppn}")
        raise RuntimeError(f"Refusing to change eppn in session from {session.common.eppn} to {user.eppn}")
    session.common.eppn = user.eppn
    session.common.is_logged_in = True
    session.common.login_source = LoginApplication.authn
    session.common.preferred_language = user.language


@acs_action(AuthnAcsAction.login)
def login_action(args: ACSArgs) -> ACSResult:
    """
    Upon successful login in the IdP, store login info in the session
    and redirect back to the app that asked for authn.
    """
    current_app.logger.info(f"User {args.user} logging in.")
    if not args.user:
        # please type checking
        return ACSResult(success=False)
    update_user_session(args.session_info, args.user)
    current_app.stats.count("login_success")

    return ACSResult(success=True)


@acs_action(AuthnAcsAction.change_password)
def chpass_action(args: ACSArgs) -> ACSResult:
    current_app.stats.count("reauthn_chpass_success")
    return _reauthn("reauthn-for-chpass", args=args)


@acs_action(AuthnAcsAction.terminate_account)
def term_account_action(args: ACSArgs) -> ACSResult:
    current_app.stats.count("reauthn_termination_success")
    return _reauthn("reauthn-for-termination", args=args)


@acs_action(AuthnAcsAction.reauthn)
def reauthn_account_action(args: ACSArgs) -> ACSResult:
    current_app.stats.count("reauthn_success")
    return _reauthn("reauthn", args=args)


def _reauthn(reason: str, args: ACSArgs) -> ACSResult:
    """
    Upon successful reauthn in the IdP, update the session and redirect back to the app that asked for reauthn.

    """
    current_app.logger.info(f"Re-authenticating user {args.user} for {reason}.")
    current_app.logger.debug(f"Data about this authentication: {args.authn_req}")
    if not args.user:
        # please type checking
        return ACSResult(success=False)

    update_user_session(args.session_info, args.user)

    return ACSResult(success=True)
