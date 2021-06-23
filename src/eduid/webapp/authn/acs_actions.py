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


from flask import redirect
from saml2.ident import code
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb import User
from eduid.webapp.authn.app import current_authn_app as current_app
from eduid.webapp.common.api.utils import sanitise_redirect_url
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.authn.acs_registry import acs_action
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.authn.utils import get_saml_attribute
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import LoginApplication, SP_AuthnRequest


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
    # TODO: re-work how information about used credentials is shared. Global state is not precise enough.
    session['eduidIdPCredentialsUsed'] = get_saml_attribute(session_info, 'eduidIdPCredentialsUsed')


@acs_action(AuthnAcsAction.login)
def login_action(session_info: SessionInfo, user: User, authndata: SP_AuthnRequest) -> WerkzeugResponse:
    """
    Upon successful login in the IdP, store login info in the session
    and redirect back to the app that asked for authn.

    :param session_info: the SAML session info
    :param user: the authenticated user
    :param authndata: data about this particular authentication event
    """
    current_app.logger.info(f'User {user} logging in.')
    update_user_session(session_info, user)
    current_app.stats.count('login_success')

    # redirect the user to the view they came from
    relay_state = sanitise_redirect_url(authndata.redirect_url)
    current_app.logger.debug(f'Redirecting to the RelayState: {relay_state}')
    response = redirect(location=relay_state)
    current_app.logger.info(f'Redirecting user {user} to {repr(relay_state)}')
    return response


@acs_action(AuthnAcsAction.change_password)
def chpass_action(session_info: SessionInfo, user: User, authndata: SP_AuthnRequest) -> WerkzeugResponse:
    current_app.stats.count('reauthn_chpass_success')
    return _reauthn('reauthn-for-chpass', session_info, user, authndata=authndata)


@acs_action(AuthnAcsAction.terminate_account)
def term_account_action(session_info: SessionInfo, user: User, authndata: SP_AuthnRequest) -> WerkzeugResponse:
    current_app.stats.count('reauthn_termination_success')
    return _reauthn('reauthn-for-termination', session_info, user, authndata=authndata)


@acs_action(AuthnAcsAction.reauthn)
def reauthn_account_action(session_info: SessionInfo, user: User, authndata: SP_AuthnRequest) -> WerkzeugResponse:
    current_app.stats.count('reauthn_success')
    return _reauthn('reauthn', session_info, user, authndata=authndata)


def _reauthn(reason: str, session_info: SessionInfo, user: User, authndata: SP_AuthnRequest) -> WerkzeugResponse:
    """
    Upon successful reauthn in the IdP, update the session and redirect back to the app that asked for reauthn.

    :param session_info: the SAML session info
    :param user: the authenticated user
    :param authndata: data about this particular authentication event
    """
    current_app.logger.info(f'Re-authenticating user {user} for {reason}.')
    current_app.logger.debug(f'Data about this authentication: {authndata}')
    update_user_session(session_info, user)

    # redirect the user to the view they came from
    redirect_url = sanitise_redirect_url(authndata.redirect_url)
    current_app.logger.debug(f'Redirecting to the redirect_url: {redirect_url}')
    return redirect(location=redirect_url)
