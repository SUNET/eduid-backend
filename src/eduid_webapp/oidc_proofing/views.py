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


@oidc_proofing_views.route('/authorization_response')
def authorization_response():
    # parse authentication response
    query_string = request.query_string.decode('utf-8')
    authn_resp = current_app.oidc_client.parse_response(AuthorizationResponse, info=query_string,
                                                        sformat='urlencoded')

    user_oidc_state = authn_resp['state']
    proofing_state = current_app.proofing_statedb.get_state_by_oidc_state(user_oidc_state)
    if not proofing_state:
        current_app.logger.error('The \'state\' parameter ({!s}) does not match a user state.'.format(user_oidc_state))
        raise ValueError('The \'state\' parameter ({!s}) does not match a user state.'.format(user_oidc_state))

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
    if id_token['nonce'] != proofing_state.nonce:
        raise ValueError('The \'nonce\' parameter does not match.')
    access_token = token_resp['access_token']

    # do userinfo request
    userinfo = current_app.oidc_client.do_user_info_request(method=current_app.config['USERINFO_ENDPOINT_METHOD'],
                                                            state=authn_resp['state'])
    if userinfo['sub'] != id_token['sub']:
        raise ValueError('The \'sub\' of userinfo does not match \'sub\' of ID Token.')

    # TODO: Using id_token, access_token and userinfo create ProofingData and
    # TODO: hand that over to the Proofing Consumer service
    current_app.logger.debug(authn_resp)
    current_app.logger.debug(token_resp)
    current_app.logger.debug(userinfo)

    # Remove users proofing state
    current_app.proofing_statedb.remove_document({'eduPersonPrincipalName': proofing_state.eppn})


@oidc_proofing_views.route('/get-state')
def get_state():
    # TODO: Authenticate user
    # TODO: Look up user in central db
    eppn = request.args.get('eppn')
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(eppn, raise_on_missing=False)
    if not proofing_state:
        state = get_unique_hash()
        nonce = get_unique_hash()
        proofing_state = OidcProofingState({'eduPersonPrincipalName': eppn, 'state': state, 'nonce': nonce})
        # Initiate proofing
        args = {
            'client_id': current_app.oidc_client.client_id,
            'response_type': 'token id_token',
            'scope': ['openid'],
            'redirect_uri': url_for('oidc_proofing.authorization_response', _external=True),
            'state': state,
            'nonce': nonce,
        }
        current_app.logger.debug('AuthorizationRequest args:')
        current_app.logger.debug(args)
        try:
            current_app.oidc_client.do_authorization_request(request_args=args, method='POST')
        except requests.exceptions.ConnectionError as e:
            msg = 'No connection to authorization endpoint: {!s}'.format(e)
            current_app.logger.error(msg)
            raise ApiException(payload={'error': msg})
        # If do_authorization_request went well save user state
        current_app.proofing_statedb.save(proofing_state)

    # Return nonce and nonce as qr code
    buf = StringIO()
    qrcode.make(proofing_state.nonce).save(buf)
    qr_b64 = buf.getvalue().encode('base64')
    # TODO: Return json response
    image_tag = '<img src="data:image/png;base64, {!s}"/>'.format(qr_b64)
    body = '<html><body><p>{!s}</p><p>{!s}</p></body></html>'.format(proofing_state.nonce, image_tag)
    return make_response(body)
