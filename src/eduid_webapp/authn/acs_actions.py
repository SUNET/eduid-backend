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
from __future__ import absolute_import

from time import time

from flask import redirect, request
from saml2.ident import code

from eduid_common.api.utils import verify_relay_state
from eduid_common.authn.acs_registry import acs_action
from eduid_common.authn.loa import get_loa
from eduid_common.authn.utils import get_saml_attribute
from eduid_common.session import session

from eduid_webapp.authn.app import current_authn_app as current_app


def update_user_session(session_info, user):
    """
    Store login info in the session

    :param session_info: the SAML session info
    :param user: the authenticated user

    :type session_info: dict
    :type user: eduid_userdb.User

    :return: None
    :rtype: None
    """
    session['_saml2_session_name_id'] = code(session_info['name_id'])
    session['eduPersonPrincipalName'] = user.eppn
    session['user_eppn'] = user.eppn  # TODO: Remove when we have deployed and IdP that sets user_eppn
    session['user_is_logged_in'] = True
    loa = get_loa(current_app.config.available_loa, session_info)
    session['eduPersonAssurance'] = loa
    session['eduidIdPCredentialsUsed'] = get_saml_attribute(session_info, 'eduidIdPCredentialsUsed')


@acs_action('login-action')
def login_action(session_info, user):
    """
    Upon successful login in the IdP, store login info in the session
    and redirect back to the app that asked for authn.

    :param session_info: the SAML session info
    :type session_info: dict

    :param user: the authenticated user
    :type user: eduid_userdb.User
    """
    current_app.logger.info("User {} logging in.".format(user))
    update_user_session(session_info, user)
    current_app.stats.count('login_success')

    # redirect the user to the view where he came from
    relay_state = verify_relay_state(request.form.get('RelayState', '/'))
    current_app.logger.debug('Redirecting to the RelayState: ' + relay_state)
    response = redirect(location=relay_state)
    # session.set_cookie(response)  #XXX: Is the explicit set_cookie needed?
    current_app.logger.info('Redirecting user {} to {!r}'.format(user, relay_state))
    return response


@acs_action('change-password-action')
def chpass_action(session_info, user):
    """
    Upon successful reauthn in the IdP,
    set a timestamp in the session (key reauthn-for-chpass)
    and redirect back to the app that asked for reauthn.

    :param session_info: the SAML session info
    :type session_info: dict

    :param user: the authenticated user
    :type user: eduid_userdb.User
    """
    current_app.stats.count('reauthn_chpass_success')
    return _reauthn('reauthn-for-chpass', session_info, user)


@acs_action('terminate-account-action')
def term_account_action(session_info, user):
    """
    Upon successful reauthn in the IdP,
    set a timestamp in the session (key reauthn-for-termination)
    and redirect back to the app that asked for reauthn.

    :param session_info: the SAML session info
    :type session_info: dict

    :param user: the authenticated user
    :type user: eduid_userdb.User
    """
    current_app.stats.count('reauthn_termination_success')
    return _reauthn('reauthn-for-termination', session_info, user)


@acs_action('reauthn-action')
def reauthn_account_action(session_info, user):
    """
    Upon successful reauthn in the IdP,
    set a timestamp in the session (key reauthn)
    and redirect back to the app that asked for reauthn.

    :param session_info: the SAML session info
    :type session_info: dict

    :param user: the authenticated user
    :type user: eduid_userdb.User
    """
    current_app.stats.count('reauthn_success')
    return _reauthn('reauthn', session_info, user)


def _reauthn(reason, session_info, user):

    current_app.logger.info("Reauthenticating user {} for {!r}.".format(user, reason))
    update_user_session(session_info, user)
    # Set reason for reauth in session
    session[reason] = int(time())

    # redirect the user to the view where he came from
    relay_state = verify_relay_state(request.form.get('RelayState', '/'))
    current_app.logger.debug('Redirecting to the RelayState: ' + relay_state)
    return redirect(location=relay_state)
