# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

from typing import Union

from flask import Blueprint, abort, make_response, redirect, request, url_for
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid_common.api.decorators import MarshalWith, require_user
from eduid_common.api.helpers import check_magic_cookie
from eduid_common.api.messages import FluxData, redirect_with_msg, success_response
from eduid_common.api.schemas.csrf import CSRFResponse
from eduid_common.api.utils import get_unique_hash, urlappend
from eduid_common.authn.acs_registry import get_action, schedule_action
from eduid_common.authn.eduid_saml2 import BadSAMLResponse
from eduid_common.authn.utils import get_location
from eduid_common.session import session

# TODO: Import FidoCredential in credentials.__init__
from eduid_userdb.credentials.fido import FidoCredential

from eduid_webapp.eidas.acs_actions import nin_verify_BACKDOOR
from eduid_webapp.eidas.app import current_eidas_app as current_app
from eduid_webapp.eidas.helpers import (
    EidasMsg,
    create_authn_request,
    create_metadata,
    parse_authn_response,
    staging_nin_remap,
)

__author__ = 'lundberg'

eidas_views = Blueprint('eidas', __name__, url_prefix='', template_folder='templates')


@eidas_views.route('/', methods=['GET'])
@MarshalWith(CSRFResponse)
@require_user
def index(user) -> FluxData:
    return success_response(payload=None, message=None)


@eidas_views.route('/verify-token/<credential_id>', methods=['GET'])
@require_user
def verify_token(user, credential_id) -> Union[FluxData, WerkzeugResponse]:
    current_app.logger.debug('verify-token called with credential_id: {}'.format(credential_id))
    redirect_url = current_app.config.token_verify_redirect_url

    # Check if requested key id is a mfa token and if the user used that to log in
    token_to_verify = user.credentials.filter(FidoCredential).find(credential_id)
    if not token_to_verify:
        return redirect_with_msg(redirect_url, EidasMsg.token_not_found)
    if token_to_verify.key not in session.get('eduidIdPCredentialsUsed', []):
        # If token was not used for login, reauthn the user
        current_app.logger.info('Token {} not used for login, redirecting to idp'.format(token_to_verify.key))
        ts_url = current_app.config.token_service_url
        reauthn_url = urlappend(ts_url, 'reauthn')
        next_url = url_for('eidas.verify_token', credential_id=credential_id, _external=True)
        # Add idp arg to next_url if set
        idp = request.args.get('idp')
        if idp:
            next_url = '{}?idp={}'.format(next_url, idp)
        return redirect('{}?next={}'.format(reauthn_url, next_url))

    # Set token key id in session
    session['verify_token_action_credential_id'] = credential_id

    # Request a authentication from idp
    required_loa = 'loa3'
    return _authn('token-verify-action', required_loa, force_authn=True)


@eidas_views.route('/verify-nin', methods=['GET'])
@require_user
def verify_nin(user):
    current_app.logger.debug('verify-nin called')

    # Backdoor for the selenium integration tests to verify NINs
    # without sending the user to an eidas idp
    if check_magic_cookie(current_app.config):
        return nin_verify_BACKDOOR()

    required_loa = 'loa3'
    return _authn('nin-verify-action', required_loa, force_authn=True)


@eidas_views.route('/mfa-authentication', methods=['GET'])
@require_user
def mfa_authentication(user):
    current_app.logger.debug('mfa-authentication called')
    required_loa = 'loa3'
    # Clear session keys used for external mfa
    del session.mfa_action
    return _authn('mfa-authentication-action', required_loa, force_authn=True)


def _authn(action, required_loa, force_authn=False, redirect_url='/'):
    """
    :param action: name of action
    :param required_loa: friendly loa name
    :param force_authn: should a new authentication be forced
    :param redirect_url: redirect url after successful authentication

    :type action: six.string_types
    :type required_loa: six.string_types
    :type force_authn: bool
    :type redirect_url: six.string_types

    :return: redirect response
    :rtype: Response
    """
    redirect_url = request.args.get('next', redirect_url)
    relay_state = get_unique_hash()
    if 'eidas_redirect_urls' not in session:
        session['eidas_redirect_urls'] = dict()
    session['eidas_redirect_urls'][relay_state] = redirect_url
    current_app.logger.info('Cached redirect_url {} for relay_state {}'.format(redirect_url, relay_state))

    idp = request.args.get('idp')
    current_app.logger.debug('Requested IdP: {}'.format(idp))
    idps = current_app.saml2_config.metadata.identity_providers()
    current_app.logger.debug('IdPs from metadata: {}'.format(idps))

    if idp in idps:
        authn_request = create_authn_request(relay_state, idp, required_loa, force_authn=force_authn)
        schedule_action(action)
        current_app.logger.info('Redirecting the user to {} for {}'.format(idp, action))
        return redirect(get_location(authn_request))
    abort(make_response('IdP ({}) not found in metadata'.format(idp), 404))


@eidas_views.route('/saml2-acs', methods=['POST'])
def assertion_consumer_service():
    """
    Assertion consumer service, receives POSTs from SAML2 IdP's
    """

    if 'SAMLResponse' not in request.form:
        abort(400)

    saml_response = request.form['SAMLResponse']
    try:
        authn_response = parse_authn_response(saml_response)

        session_info = authn_response.session_info()

        current_app.logger.debug('Auth response:\n{!s}\n\n'.format(authn_response))
        current_app.logger.debug('Session info:\n{!s}\n\n'.format(session_info))

        # Remap nin in staging environment
        if current_app.config.environment == 'staging':
            session_info = staging_nin_remap(session_info)

        action = get_action()
        return action(session_info)
    except BadSAMLResponse as e:
        current_app.logger.error('BadSAMLResponse: {}'.format(e))
        return make_response(str(e), 400)


@eidas_views.route('/saml2-metadata')
def metadata():
    """
    Returns an XML with the SAML 2.0 metadata for this
    SP as configured in the saml2_settings.py file.
    """
    data = create_metadata(current_app.saml2_config)
    response = make_response(data.to_string(), 200)
    response.headers['Content-Type'] = "text/xml; charset=utf8"
    return response
