# -*- coding: utf-8 -*-
from __future__ import absolute_import

from flask import request, session, url_for, make_response
from flask import current_app, Blueprint
from oic.oic.message import AuthorizationResponse
import requests
import qrcode
import qrcode.image.svg
from eduid_common.api.utils import get_unique_hash, StringIO
from eduid_common.api.exceptions import ApiException
from eduid_userdb.proofing import OidcProofingState


__author__ = 'lundberg'

"""
OIDC code very inspired by https://github.com/its-dirg/Flask-pyoidc
"""

oidc_proofing_views = Blueprint('oidc_proofing', __name__, url_prefix='')


@oidc_proofing_views.route('/authorization-response')
def authorization_response():
    # parse authentication response
    current_app.logger.debug('Authorization response received')
    query_string = request.query_string.decode('utf-8')
    authn_resp = current_app.oidc_client.parse_response(AuthorizationResponse, info=query_string,
                                                        sformat='urlencoded')
    user_oidc_state = authn_resp['state']
    proofing_state = current_app.proofing_statedb.get_state_by_oidc_state(user_oidc_state)
    if not proofing_state:
        msg = 'The \'state\' parameter ({!s}) does not match a user state.'.format(user_oidc_state)
        current_app.logger.error(msg)
        raise ApiException(payload={'error': msg})

    current_app.logger.debug('Proofing state {!s} for user {!s} found'.format(proofing_state.state,
                                                                              proofing_state.eppn))
    # do token request
    args = {
        'code': authn_resp['code'],
        'redirect_uri': url_for('oidc_proofing.authorization_response', _external=True)
    }
    current_app.logger.debug('Trying to do token request: {!s}'.format(args))
    token_resp = current_app.oidc_client.do_access_token_request(scope='openid', state=authn_resp['state'],
                                                                 request_args=args,
                                                                 authn_method='client_secret_basic')
    current_app.logger.debug('token response received: {!s}'.format(token_resp))
    id_token = token_resp['id_token']
    if id_token['nonce'] != proofing_state.nonce:
        current_app.logger.error('The \'nonce\' parameter does not match for user {!s}.'.format(proofing_state.eppn))
        raise ApiException(payload={'error': 'The \'nonce\' parameter does not match match.'})

    access_token = token_resp['access_token']
    current_app.logger.debug('Trying to do userinfo request: {!s}')
    # do userinfo request
    userinfo = current_app.oidc_client.do_user_info_request(method=current_app.config['USERINFO_ENDPOINT_METHOD'],
                                                            state=authn_resp['state'])
    current_app.logger.debug('userinfo received: {!s}'.format(userinfo))
    if userinfo['sub'] != id_token['sub']:
        current_app.logger.error('The \'sub\' of userinfo does not match \'sub\' of ID Token for user {!s}.'.format(
            proofing_state.eppn))
        raise ApiException(payload={'The \'sub\' of userinfo does not match \'sub\' of ID Token'})

    # TODO: Using id_token, access_token and userinfo create ProofingData and
    # TODO: hand that over to the Proofing Consumer service

    # Remove users proofing state
    current_app.proofing_statedb.remove_state(proofing_state)
    return make_response('OK', 200)


@oidc_proofing_views.route('/get-state')
def get_state():
    # TODO: Authenticate user
    # TODO: Look up user in central db
    eppn = request.args.get('eppn')
    current_app.logger.debug('Getting state for user with eppn {!s}.'.format(eppn))
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(eppn, raise_on_missing=False)
    if not proofing_state:
        current_app.logger.debug('No proofing state found, initializing new proofing flow.'.format(eppn))
        state = get_unique_hash()
        nonce = get_unique_hash()
        proofing_state = OidcProofingState({'eduPersonPrincipalName': eppn, 'state': state, 'nonce': nonce})
        # Initiate proofing
        args = {
            'client_id': current_app.oidc_client.client_id,
            'response_type': 'code id_token token',
            'response_mode': 'query',
            'scope': ['openid'],
            'redirect_uri': url_for('oidc_proofing.authorization_response', _external=True),
            'state': state,
            'nonce': nonce,
        }
        current_app.logger.debug('AuthorizationRequest args:')
        current_app.logger.debug(args)
        try:
            response = requests.post(current_app.oidc_client.authorization_endpoint, data=args)
        except requests.exceptions.ConnectionError as e:
            msg = 'No connection to authorization endpoint: {!s}'.format(e)
            current_app.logger.error(msg)
            raise ApiException(payload={'error': msg})
        # If do_authorization_request went well save user state
        if response.status_code == 200:
            current_app.logger.debug('Authentication request delivered to provider {!s}'.format(
                current_app.config['PROVIDER_CONFIGURATION_INFO']['issuer']))
            current_app.proofing_statedb.save(proofing_state)
            current_app.logger.debug('Proofing state {!s} for user {!s} saved'.format(proofing_state.state, eppn))
        else:
            payload = {'error': response.reason, 'message': response.content}
            raise ApiException(status_code=response.status_code, payload=payload)
    # Return nonce and nonce as qr code
    current_app.logger.debug('Returning nonce for user {!s}'.format(eppn))
    buf = StringIO()
    qrcode.make(proofing_state.nonce).save(buf)
    qr_b64 = buf.getvalue().encode('base64')
    # TODO: Return json response
    image_tag = '<img src="data:image/png;base64, {!s}"/>'.format(qr_b64)
    body = '<html><body><p>{!s}</p><p>{!s}</p></body></html>'.format(proofing_state.nonce, image_tag)
    return make_response(body)

