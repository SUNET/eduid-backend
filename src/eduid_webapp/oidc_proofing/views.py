# -*- coding: utf-8 -*-
from __future__ import absolute_import

from flask import request, make_response
from flask import current_app, Blueprint
from flask_apispec import marshal_with, use_kwargs
from oic.oic.message import AuthorizationResponse, ClaimsRequest, Claims
from operator import itemgetter
import requests
import qrcode
import qrcode.image.svg
import json
from eduid_userdb.proofing import ProofingUser
from eduid_userdb.nin import Nin
from eduid_common.api.utils import get_unique_hash, StringIO
from eduid_common.api.decorators import require_user, require_eppn
from eduid_common.api.exceptions import ApiException
from eduid_userdb.proofing import OidcProofingState
from eduid_webapp.oidc_proofing import schemas
from eduid_webapp.oidc_proofing.mock_proof import Proof, DocumentDoesNotExist

__author__ = 'lundberg'

"""
OIDC code very inspired by https://github.com/its-dirg/Flask-pyoidc
"""

oidc_proofing_views = Blueprint('oidc_proofing', __name__, url_prefix='')


@oidc_proofing_views.route('/authorization-response')
def authorization_response():
    # parse authentication response
    query_string = request.query_string.decode('utf-8')
    current_app.logger.debug('query_string: {!s}'.format(query_string))
    authn_resp = current_app.oidc_client.parse_response(AuthorizationResponse, info=query_string,
                                                        sformat='urlencoded')
    current_app.logger.debug('Authorization response received: {!s}'.format(authn_resp))

    if authn_resp.get('error'):
        current_app.logger.error('AuthorizationError {!s} - {!s} ({!s})'.format(request.host, authn_resp['error'],
                                                                                authn_resp.get('error_message'),
                                                                                authn_resp.get('error_uri')))
        return make_response('OK', 200)

    user_oidc_state = authn_resp['state']
    proofing_state = current_app.proofing_statedb.get_state_by_oidc_state(user_oidc_state)
    if not proofing_state:
        msg = 'The \'state\' parameter ({!s}) does not match a user state.'.format(user_oidc_state)
        current_app.logger.error(msg)
        return make_response('OK', 200)
    current_app.logger.debug('Proofing state {!s} for user {!s} found'.format(proofing_state.state,
                                                                              proofing_state.eppn))
    # TODO: We should save the auth response code to the proofing state to be able to continue a failed attempt
    # do token request
    args = {
        'code': authn_resp['code'],
        'redirect_uri': current_app.config['AUTHORIZATION_RESPONSE_URI']
    }
    current_app.logger.debug('Trying to do token request: {!s}'.format(args))
    # TODO: What and where should be save from the token response
    token_resp = current_app.oidc_client.do_access_token_request(scope='openid', state=authn_resp['state'],
                                                                 request_args=args,
                                                                 authn_method='client_secret_basic')
    current_app.logger.debug('token response received: {!s}'.format(token_resp))
    id_token = token_resp['id_token']
    if id_token['nonce'] != proofing_state.nonce:
        current_app.logger.error('The \'nonce\' parameter does not match for user {!s}.'.format(proofing_state.eppn))
        return make_response('OK', 200)

    # do userinfo request
    current_app.logger.debug('Trying to do userinfo request:')
    # TODO: Do we need to save anything else from the userinfo response
    userinfo = current_app.oidc_client.do_user_info_request(method=current_app.config['USERINFO_ENDPOINT_METHOD'],
                                                            state=authn_resp['state'])
    current_app.logger.debug('userinfo received: {!s}'.format(userinfo))
    if userinfo['sub'] != id_token['sub']:
        current_app.logger.error('The \'sub\' of userinfo does not match \'sub\' of ID Token for user {!s}.'.format(
            proofing_state.eppn))
        return make_response('OK', 200)

    # TODO: Check nin against OidcProofingState
    nin = userinfo['identity']
    # TODO: Break out in parts to be able to continue the proofing process after a successful authorization response
    # TODO: even if the token request, userinfo request or something internal fails
    am_user = current_app.central_userdb.get_user_by_eppn(proofing_state.eppn)
    user = ProofingUser(data=am_user.to_dict())
    nin = Nin(number=nin, application='eduid_oidc_proofing', verified=True, primary=False)

    # Save user to private db
    if user.nins.primary is None:  # No primary NIN found, make the only verified NIN primary
        nin.is_primary = True
    user.nins.add(nin)

    # User from central db is as up to date as it can be no need to check for modified time
    user.modified_ts = True
    # XXX: Send proofing data to some kind of proofing log
    current_app.proofing_userdb.save(user, check_sync=False)

    # TODO: Need to decide where to "steal" NIN if multiple users have the NIN verified
    # Ask am to sync user to central db
    try:
        current_app.logger.info('Request sync for user {!s}'.format(user))
        result = current_app.am_relay.request_user_sync(user)
        current_app.logger.info('Sync result for user {!s}: {!s}'.format(user, result))
    except Exception as e:
        current_app.logger.error('Sync request failed for user {!s}'.format(user))
        current_app.logger.error('Exception: {!s}'.format(e))
        # TODO: Need to able to retry this
        return make_response('OK', 200)

    # TODO: Remove saving of proof
    # Save proof for demo purposes
    proof_data = {
        'eduPersonPrincipalName': proofing_state.eppn,
        'authn_resp': authn_resp.to_dict(),
        'token_resp': token_resp.to_dict(),
        'userinfo': userinfo.to_dict()
    }

    current_app.proofdb.save(Proof(data=proof_data))

    # Remove users proofing state
    current_app.proofing_statedb.remove_state(proofing_state)
    return make_response('OK', 200)


@oidc_proofing_views.route('/proofing', methods=['POST'])
@marshal_with(schemas.NonceResponseSchema)
@require_user
def proofing(user):
    data = json.loads(request.get_data())
    schema = schemas.OidcProofingRequestSchema().load(data)
    if schema.errors:
        current_app.logger.error(schema.errors)
        raise ApiException('POST_OPENID_FAIL', payload={'error': schema.errors})

    current_app.logger.debug('Getting state for user {!s}.'.format(user))

    # TODO: Check if a user has a valid letter proofing
    # For now a user can just have one verified NIN
    if len(user.nins.to_list()) > 0:
        raise ApiException('POST_OPENID_FAIL', 'User is already verified', status_code=200)

    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)
    if not proofing_state:
        current_app.logger.debug('No proofing state found for user {!s}. Initializing new proofing flow.'.format(user))
        state = get_unique_hash()
        nonce = get_unique_hash()
        # TODO: Read nin from data and use in OidcProofingState
        proofing_state = OidcProofingState({'eduPersonPrincipalName': user.eppn, 'state': state, 'nonce': nonce})
        # Initiate proofing
        oidc_args = {
            'client_id': current_app.oidc_client.client_id,
            'response_type': 'code',
            'scope': ['openid'],
            'redirect_uri': current_app.config['AUTHORIZATION_RESPONSE_URI'],
            'state': state,
            'nonce': nonce,
            'claims': ClaimsRequest(userinfo=Claims(identity=None)).to_json()
        }
        current_app.logger.debug('AuthenticationRequest args:')
        current_app.logger.debug(oidc_args)
        try:
            response = requests.post(current_app.oidc_client.authorization_endpoint, data=oidc_args)
        except requests.exceptions.ConnectionError as e:
            msg = 'No connection to authorization endpoint: {!s}'.format(e)
            current_app.logger.error(msg)
            raise ApiException('POST_OPENID_FAIL', payload={'message': msg})
        # If authentication request went well save user state
        if response.status_code == 200:
            current_app.logger.debug('Authentication request delivered to provider {!s}'.format(
                current_app.config['PROVIDER_CONFIGURATION_INFO']['issuer']))
            current_app.proofing_statedb.save(proofing_state)
            current_app.logger.debug('Proofing state {!s} for user {!s} saved'.format(proofing_state.state, user))
        else:
            payload = {'reason': response.reason, 'message': response.content}
            raise ApiException('POST_OPENID_FAIL', status_code=response.status_code, payload=payload)
    # Return nonce and nonce as qr code
    current_app.logger.debug('Returning nonce for user {!s}'.format(user))
    buf = StringIO()
    qrcode.make(proofing_state.nonce).save(buf)
    qr_b64 = buf.getvalue().encode('base64')
    ret = {
        'type': 'POST_OPENID_SUCCESS',
        'payload': {
            'nonce': proofing_state.nonce,
            'qrcode': '<img src="data:image/png;base64, {!s}"/>'.format(qr_b64),
        }
    }
    return ret


# TODO Remove after demo
@oidc_proofing_views.route('/proofs', methods=['GET'])
@marshal_with(schemas.ProofResponseSchema)
@require_eppn
def proofs(eppn):
    current_app.logger.debug('Getting proofs for user with eppn {!s}.'.format(eppn))
    try:
        proof_data = current_app.proofdb.get_proofs_by_eppn(eppn)
    except DocumentDoesNotExist:
        return {'proofs': []}
    data = []
    for proof in proof_data:
        tmp = proof.to_dict()
        del tmp['_id']
        data.append(tmp)
    data = sorted(data, key=itemgetter('modified_ts'), reverse=True)
    return {'proofs': data}

