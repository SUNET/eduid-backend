# -*- coding: utf-8 -*-
from __future__ import absolute_import

from flask import request, session, redirect, abort
from flask import current_app, Blueprint
from oic import rndstr
from oic.oic.message import AuthorizationResponse

__author__ = 'lundberg'

"""
OIDC code very inspired by https://github.com/its-dirg/Flask-pyoidc
"""

oidc_proofing_views = Blueprint('oidc_proofing', __name__, url_prefix='')


@oidc_proofing_views.route('/authorization_response')
def authorization_response():
    # parse authentication response
    query_string = request.query_string.decode('utf-8')
    authn_resp = current_app.oidc_client.parse_response(AuthorizationResponse, info=query_string,
                                                        sformat='urlencoded')

    # TODO: Get user data by state
    user_data = None
    if not user_data:
        current_app.logger.error('The \'state\' parameter ({!s}) does not match a user state.'.format(
            authn_resp['state']))
        raise ValueError('The \'state\' parameter ({!s}) does not match a user state.'.format(authn_resp['state']))

    # do token request
    args = {
        'code': authn_resp['code'],
        'redirect_uri': current_app.oidc_client.registration_response['redirect_uris'][0],
        'client_id': current_app.oidc_client.client_id,
        'client_secret': current_app.oidc_client.client_secret
    }
    token_resp = current_app.oidc_client.do_access_token_request(scope='openid', state=authn_resp['state'],
                                                                 request_args=args,
                                                                 authn_method='client_secret_basic')
    id_token = token_resp['id_token']
    if id_token['nonce'] != user_data['nonce']:
        raise ValueError('The \'nonce\' parameter does not match.')
    access_token = token_resp['access_token']

    # do userinfo request
    userinfo = current_app.oidc_client.do_user_info_request(method=USERINFO_ENDPOINT_METHOD, state=authn_resp['state'])
    if userinfo['sub'] != id_token['sub']:
        raise ValueError('The \'sub\' of userinfo does not match \'sub\' of ID Token.')

    # TODO: Using id_token, access_token and userinfo create ProofingData and
    # TODO: hand that over to the Proofing Consumer service


@oidc_proofing_views.route('/get-state')
def get_state():
    # TODO: Look up user data in oidc_proofing db
    user_data = None
    if not user_data:
        state = rndstr()
        nonce = rndstr()
        # Initiate proofing
        args = {
            'client_id': current_app.oidc_client.client_id,
            'response_type': 'code',
            'scope': ['openid'],
            'redirect_uri': current_app.oidc_client.registration_response['redirect_uris'][0],
            'state': state,
            'nonce': nonce,
        }
        auth_req = current_app.oidc_client.construct_AuthorizationRequest(request_args=args)
        response = current_app.oidc_client.do_authorization_request(request=auth_req, method='POST')
        if response.status_code != 200:
            return abort()
        # Save user_data to db
    # Return nonce and nonce as qr code

