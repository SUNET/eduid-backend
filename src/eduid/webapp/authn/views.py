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
import uuid
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
from eduid.webapp.common.api.utils import sanitise_redirect_url
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.authn.acs_registry import get_action
from eduid.webapp.common.authn.cache import IdentityCache, StateCache
from eduid.webapp.common.authn.eduid_saml2 import get_authn_request, process_assertion, saml_logout
from eduid.webapp.common.authn.utils import check_previous_identification, get_location
from eduid.webapp.common.session import EduidSession, session
from eduid.webapp.common.session.namespaces import AuthnRequestRef, LoginApplication, SP_AuthnRequest

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
    redirect_url = sanitise_redirect_url(request.args.get('next'), current_app.conf.saml2_login_redirect_url)

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

    _authn_id = AuthnRequestRef(str(uuid.uuid4()))
    # Filter out any previous authns with the same post_authn_action, both to keep the size of the session
    # below an upper bound, and because we currently need to use the post_authn_action value to find the
    # authn data for a specific action.
    session.authn.sp.authns = {k: v for k, v in session.authn.sp.authns.items() if v.post_authn_action != action}
    session.authn.sp.authns[_authn_id] = SP_AuthnRequest(post_authn_action=action, redirect_url=redirect_url)

    authn_request = get_authn_request(
        saml2_config=current_app.saml2_config,
        session=session,
        relay_state='',
        authn_id=_authn_id,
        selected_idp=idp,
        force_authn=force_authn,
        sign_alg=current_app.conf.authn_sign_alg,
        digest_alg=current_app.conf.authn_digest_alg,
    )
    current_app.logger.info(f'Redirecting the user to the IdP for {action} (redirect_url {redirect_url})')
    current_app.logger.debug(f'Stored SP_AuthnRequest[{_authn_id}]: {session.authn.sp.authns[_authn_id]}')
    _idp_redirect_url = get_location(authn_request)
    current_app.logger.debug(f'Redirecting user to the IdP: {_idp_redirect_url}')
    return redirect(_idp_redirect_url)


@authn_views.route('/saml2-acs', methods=['POST'])
def assertion_consumer_service():
    """
    Assertion consumer service, receives POSTs from SAML2 IdP's
    """
    assertion = process_assertion(
        form=request.form,
        sp_data=session.authn.sp,
        error_redirect_url=current_app.conf.unsolicited_response_redirect_url,
        strip_suffix=current_app.conf.saml2_strip_saml_user_suffix,
    )
    if isinstance(assertion, WerkzeugResponse):
        return assertion
    current_app.logger.debug(f'Auth response:\n{assertion}\n\n')

    action = get_action(default_action=AuthnAcsAction.login, authndata=assertion.authndata)
    return action(assertion.session_info, assertion.user, authndata=assertion.authndata)


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
    #   - saml2_logout_redirect_url from config
    logout_redirect_url = current_app.conf.saml2_logout_redirect_url
    _next_page = request.form.get('RelayState') or logout_redirect_url
    # Since the chosen destination is possibly user input, it must be sanitised.
    next_page = sanitise_redirect_url(_next_page, logout_redirect_url)

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
                f'The session does not contain the subject id for user {session.common.eppn}, performing local logout'
            )
            session.clear()
            return redirect(next_page)
        current_app.logger.debug(f'Logging out user using name-id from session: {subject_id}')
        http_info = client.handle_logout_request(
            request.form['SAMLRequest'], subject_id, BINDING_HTTP_REDIRECT, relay_state=request.form['RelayState']
        )
        state.sync()
        session.clear()
        location = get_location(http_info)
        # location comes from federation metadata and must be considered trusted, no need to sanitise
        current_app.logger.debug(f'Returning redirect to IdP SLO service: {location}')
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
