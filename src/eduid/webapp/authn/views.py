#
# Copyright (c) 2016 NORDUnet A/S
# Copyright (c) 2020 SUNET
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
from typing import Optional

from flask import Blueprint, abort, make_response, redirect, request
from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.ident import decode
from saml2.metadata import entity_descriptor
from saml2.saml import NameID
from werkzeug.exceptions import Forbidden
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.authn import acs_actions  # acs_action needs to be imported to be loaded
from eduid.webapp.authn.app import current_authn_app as current_app
from eduid.webapp.common.api.utils import verify_relay_state
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.authn.acs_registry import get_action, schedule_action
from eduid.webapp.common.authn.cache import IdentityCache, StateCache
from eduid.webapp.common.authn.eduid_saml2 import (
    BadSAMLResponse,
    UnsolicitedResponse,
    authenticate,
    get_authn_request,
    get_authn_response,
    saml_logout,
)
from eduid.webapp.common.authn.utils import check_previous_identification, get_location
from eduid.webapp.common.session import EduidSession, session
from eduid.webapp.common.session.namespaces import LoginApplication

assert acs_actions  # make sure nothing optimises away the import of this, as it is needed to execute @acs_actions

authn_views = Blueprint('authn', __name__, url_prefix='')


@authn_views.route('/login')
def login() -> WerkzeugResponse:
    """
    login view, redirects to SAML2 IdP
    """
    return _authn(AuthnAcsAction.login)


@authn_views.route('/reauthn')
def reauthn() -> WerkzeugResponse:
    """
    login view with force authn, redirects to SAML2 IdP
    """
    # OLD
    session['user_is_logged_in'] = False
    # NEW
    session.common.is_logged_in = False
    return _authn(AuthnAcsAction.reauthn, force_authn=True)


@authn_views.route('/chpass')
def chpass() -> WerkzeugResponse:
    """
    Reauthn view, sends a SAML2 reauthn request to the IdP.
    """
    return _authn(AuthnAcsAction.change_password, force_authn=True)


@authn_views.route('/terminate')
def terminate() -> WerkzeugResponse:
    """
    Reauthn view, sends a SAML2 reauthn request to the IdP.
    """
    return _authn(AuthnAcsAction.terminate_account, force_authn=True)


def _authn(action: AuthnAcsAction, force_authn=False) -> WerkzeugResponse:
    redirect_url = current_app.conf.saml2_login_redirect_url
    relay_state = verify_relay_state(request.args.get('next', redirect_url), redirect_url)

    # In the future, we might want to support choosing the IdP somehow but for now
    # the only supported configuration is one (1) IdP.
    _configured_idps = current_app.saml2_config.getattr('idp')
    if len(_configured_idps) != 1:
        current_app.logger.error(f'Unknown SAML2 idp config: {repr(_configured_idps)}')
        raise RuntimeError('Unknown SAML2 idp config')
    # For now, we will only ever use the single configured IdP
    idp = list(_configured_idps.keys())[0]
    # Be somewhat backwards compatible and check the provided IdP parameter
    _requested_idp = request.args.get('idp')
    if _requested_idp and _requested_idp != idp:
        current_app.logger.error(f'Requested IdP {_requested_idp} not allowed')
        raise Forbidden('Requested IdP not allowed')

    authn_request = get_authn_request(
        current_app.saml2_config,
        session,
        relay_state,
        idp,
        force_authn=force_authn,
        sign_alg=current_app.conf.authn_sign_alg,
        digest_alg=current_app.conf.authn_digest_alg,
    )
    schedule_action(action, session.authn.sp)
    current_app.logger.info(f'Redirecting the user to the IdP for {action} (relay state {relay_state})')
    return redirect(get_location(authn_request))


@authn_views.route('/saml2-acs', methods=['POST'])
def assertion_consumer_service():
    """
    Assertion consumer service, receives POSTs from SAML2 IdP's
    """
    if 'SAMLResponse' not in request.form:
        abort(400)
    xmlstr = request.form['SAMLResponse']
    try:
        session_info = get_authn_response(current_app.saml2_config, session, xmlstr)
        current_app.logger.debug('Trying to locate the user authenticated by the IdP')
        user = authenticate(
            session_info, strip_suffix=current_app.conf.saml2_strip_saml_user_suffix, userdb=current_app.central_userdb
        )
        if user is None:
            current_app.logger.error('Could not find the user identified by the IdP')
            raise Forbidden("Access not authorized")
        action = get_action(default_action=AuthnAcsAction.login, sp_data=session.authn.sp)
        return action(session_info, user)
    except UnsolicitedResponse:
        unsolicited_response_redirect_url = current_app.conf.unsolicited_response_redirect_url
        current_app.logger.info(f'Unsolicited response. Redirecting user to {unsolicited_response_redirect_url}')
        return redirect(unsolicited_response_redirect_url)
    except BadSAMLResponse as e:
        current_app.logger.error(e)
        raise Forbidden(f'Bad SAML response: {e}')


def _get_authn_name_id(session: EduidSession) -> Optional[NameID]:
    """
    Get the SAML2 NameID of the currently logged in user.
    :param session: The current session object
    :return: NameID
    """
    if not session.authn.name_id:
        return None
    try:
        return decode(session.authn.name_id)
    except KeyError:
        return None


@authn_views.route('/logout', methods=['GET'])
def logout():
    """
    SAML Logout Request initiator.
    This view initiates the SAML2 Logout request
    using the pysaml2 library to create the LogoutRequest.
    """
    eppn = session.common.eppn

    next = request.args.get('next', '')
    location = next or current_app.conf.saml2_logout_redirect_url

    if eppn is None:
        current_app.logger.info('Session cookie has expired, no logout action needed')
        return redirect(location)

    user = current_app.central_userdb.get_user_by_eppn(eppn)

    current_app.logger.debug('Logout process started for user {}'.format(user))

    return saml_logout(current_app.saml2_config, user, location)


@authn_views.route('/saml2-ls', methods=['POST'])
def logout_service():
    """SAML Logout Response endpoint
    The IdP will send the logout response to this view,
    which will process it with pysaml2 help and log the user
    out.
    Note that the IdP can request a logout even when
    we didn't initiate the process as a single logout
    request started by another SP.
    """
    current_app.logger.debug('Logout service started')

    state = StateCache(session.authn.sp.pysaml2_dicts)
    identity = IdentityCache(session.authn.sp.pysaml2_dicts)
    client = Saml2Client(current_app.saml2_config, state_cache=state, identity_cache=identity)

    # Pick a 'next' destination from these alternatives (most preferred first):
    #   - RelayState from request.form
    #   - next from request.args
    #   - session.authn.next
    #   - saml2_logout_redirect_url from config
    logout_redirect_url = current_app.conf.saml2_logout_redirect_url
    _next_page = request.form.get('RelayState') or request.args.get('next') or session.authn.next or logout_redirect_url
    # Since the chosen destination is possibly user input, it must be sanitised.
    next_page = verify_relay_state(_next_page, logout_redirect_url)

    if 'SAMLResponse' in request.form:  # we started the logout
        current_app.logger.debug('Receiving a logout response from the IdP')
        response = client.parse_logout_request_response(request.form['SAMLResponse'], BINDING_HTTP_REDIRECT)
        state.sync()
        if response and response.status_ok():
            session.clear()
            return redirect(next_page)
        else:
            current_app.logger.error('Unknown error during the logout')
            abort(400)

    # logout started by the IdP
    elif 'SAMLRequest' in request.form:
        current_app.logger.debug('Receiving a logout request from the IdP')
        subject_id = _get_authn_name_id(session)
        if subject_id is None:
            current_app.logger.warning(
                'The session does not contain the subject id for user {0} '
                'Performing local logout'.format(session['eduPersonPrincipalName'])
            )
            session.clear()
            return redirect(next_page)
        else:
            http_info = client.handle_logout_request(
                request.form['SAMLRequest'], subject_id, BINDING_HTTP_REDIRECT, relay_state=request.form['RelayState']
            )
            state.sync()
            location = get_location(http_info)
            session.clear()
            return redirect(location)
    current_app.logger.error('No SAMLResponse or SAMLRequest parameter found')
    abort(400)


@authn_views.route('/signup-authn', methods=['GET', 'POST'])
def signup_authn():
    current_app.logger.debug('Authenticating signing up user')
    location_on_fail = current_app.conf.signup_authn_failure_redirect_url
    location_on_success = current_app.conf.signup_authn_success_redirect_url

    eppn = check_previous_identification(session.signup)
    if eppn is not None:
        current_app.logger.info("Starting authentication for user from signup with eppn: {})".format(eppn))
        try:
            user = current_app.central_userdb.get_user_by_eppn(eppn)
        except current_app.central_userdb.exceptions.UserDoesNotExist:
            current_app.logger.error('No user with eduPersonPrincipalName = {} found'.format(eppn))
        except current_app.central_userdb.exceptions.MultipleUsersReturned:
            current_app.logger.error("There are more than one user with eduPersonPrincipalName = {}".format(eppn))
        else:
            if user.locked_identity.count > 0:
                # This user has previously verified their account and is not new, this should not happen.
                current_app.logger.error('Not new user {} tried to log in using signup authn'.format(user))
                return redirect(location_on_fail)
            # OLD
            session['eduPersonPrincipalName'] = user.eppn
            session['user_eppn'] = user.eppn
            session['user_is_logged_in'] = True
            # NEW
            session.common.eppn = user.eppn
            session.common.is_logged_in = True
            session.common.login_source = LoginApplication.signup

            response = redirect(location_on_success)
            current_app.logger.info(
                'Successful authentication, redirecting user {} to {}'.format(user, location_on_success)
            )
            return response

    current_app.logger.info('Signup authn failed, redirecting user to {}'.format(location_on_fail))
    return redirect(location_on_fail)


@authn_views.route('/saml2-metadata')
def metadata():
    """
    Returns an XML with the SAML 2.0 metadata for this
    SP as configured in the saml2_settings.py file.
    """
    metadata = entity_descriptor(current_app.saml2_config)
    response = make_response(metadata.to_string(), 200)
    response.headers['Content-Type'] = "text/xml; charset=utf8"
    return response
