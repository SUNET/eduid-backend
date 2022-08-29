#
# Copyright (c) 2016 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#


from eduid.userdb import User
from eduid.webapp.authn.app import current_authn_app as current_app
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, acs_action
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import LoginApplication
from saml2.ident import code


def update_user_session(session_info: SessionInfo, user: User) -> None:
    """
    Store login info in the session

    :param session_info: the SAML session info
    :param user: the authenticated user

    :return: None
    """
    session.authn.name_id = code(session_info['name_id'])
    if session.common.eppn and session.common.eppn != user.eppn:
        current_app.logger.warning(f'Refusing to change eppn in session from {session.common.eppn} to {user.eppn}')
        raise RuntimeError(f'Refusing to change eppn in session from {session.common.eppn} to {user.eppn}')
    session.common.eppn = user.eppn
    session.common.is_logged_in = True
    session.common.login_source = LoginApplication.authn
    session.common.preferred_language = user.language


@acs_action(AuthnAcsAction.login)
def login_action(args: ACSArgs) -> ACSResult:
    """
    Upon successful login in the IdP, store login info in the session
    and redirect back to the app that asked for authn.

    :param session_info: the SAML session info
    :param user: the authenticated user
    :param authndata: data about this particular authentication event
    """
    current_app.logger.info(f'User {args.user} logging in.')
    if not args.user:
        # please type checking
        return ACSResult(success=False)
    update_user_session(args.session_info, args.user)
    current_app.stats.count('login_success')

    return ACSResult(success=True)


@acs_action(AuthnAcsAction.change_password)
def chpass_action(args: ACSArgs) -> ACSResult:
    current_app.stats.count('reauthn_chpass_success')
    return _reauthn('reauthn-for-chpass', args=args)


@acs_action(AuthnAcsAction.terminate_account)
def term_account_action(args: ACSArgs) -> ACSResult:
    current_app.stats.count('reauthn_termination_success')
    return _reauthn('reauthn-for-termination', args=args)


@acs_action(AuthnAcsAction.reauthn)
def reauthn_account_action(args: ACSArgs) -> ACSResult:
    current_app.stats.count('reauthn_success')
    return _reauthn('reauthn', args=args)


def _reauthn(reason: str, args: ACSArgs) -> ACSResult:
    """
    Upon successful reauthn in the IdP, update the session and redirect back to the app that asked for reauthn.

    :param session_info: the SAML session info
    :param user: the authenticated user
    :param authndata: data about this particular authentication event
    """
    current_app.logger.info(f'Re-authenticating user {args.user} for {reason}.')
    current_app.logger.debug(f'Data about this authentication: {args.authn_req}')
    if not args.user:
        # please type checking
        return ACSResult(success=False)

    update_user_session(args.session_info, args.user)

    return ACSResult(success=True)
