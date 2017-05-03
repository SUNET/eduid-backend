# -*- coding: utf-8 -*-
from __future__ import absolute_import

import requests
import qrcode
import qrcode.image.svg
import json

from flask import request, make_response, url_for
from flask import current_app, Blueprint
from oic.oic.message import AuthorizationResponse, ClaimsRequest, Claims

from eduid_userdb.proofing import ProofingUser
from eduid_userdb.logs import OidcProofing
from eduid_userdb.exceptions import DocumentDoesNotExist
from eduid_common.api.utils import StringIO
from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_webapp.oidc_proofing import schemas
from eduid_webapp.oidc_proofing import helpers

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

    # Check if the token from the authn response matches the token we created when making the auth request
    authorization_header = request.headers.get('Authorization')
    if authorization_header != 'Bearer {}'.format(proofing_state.token):
        current_app.logger.error('The authorization token ({!s}) did not match the expected'.format(
            authorization_header))
        return make_response('FORBIDDEN', 403)

    # TODO: We should save the auth response code to the proofing state to be able to continue a failed attempt
    # do token request
    args = {
        'code': authn_resp['code'],
        'redirect_uri': url_for('oidc_proofing.authorization_response', _external=True)
    }
    current_app.logger.debug('Trying to do token request: {!s}'.format(args))
    # TODO: What should be save from the token response and where?
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

    # TODO: Break out in parts to be able to continue the proofing process after a successful authorization response
    # TODO: even if the token request, userinfo request or something internal fails
    am_user = current_app.central_userdb.get_user_by_eppn(proofing_state.eppn)
    user = ProofingUser(data=am_user.to_dict())

    # A user can only have one NIN verified at this time
    if user.nins.primary is None:
        success = False
        # Handle userinfo differently depending on data in userinfo
        if userinfo.get('identity'):
            current_app.logger.info('Handling userinfo as generic seleg vetting for user {}'.format(user))
            user, success = helpers.handle_seleg_userinfo(user, proofing_state, userinfo)
            vetting_by = 'seleg'
        elif userinfo.get('freja_proofing'):
            current_app.logger.info('Handling userinfo as freja vetting for user {}'.format(user))
            user, success = helpers.handle_freja_userinfo(user, proofing_state, userinfo)
            vetting_by = 'verisec'

        # If user was updated successfully continue with logging the proof and saving the user to central db
        if success:
            # Send proofing data to the proofing log
            current_app.logger.info('Getting address for user {!r}'.format(user))
            # Lookup official address via Navet
            address = current_app.msg_relay.get_postal_address(proofing_state.nin.number)
            # Transaction id is the same data as used for the QR code or seed data for the freja app
            transaction_id = '1' + json.dumps({'nonce': proofing_state.nonce, 'token': proofing_state.token})
            oidc_proof = OidcProofing(user, created_by='oidc_proofing', nin=proofing_state.nin.number,
                                      vetting_by=vetting_by, transaction_id=transaction_id, user_postal_address=address,
                                      proofing_version='2017v1')
            if current_app.proofing_log.save(oidc_proof):
                # User from central db is as up to date as it can be no need to check for modified time
                user.modified_ts = True
                # Save user to private db
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
                    # TODO: Need to able to retry

    # Remove users proofing state
    current_app.proofing_statedb.remove_state(proofing_state)
    return make_response('OK', 200)


@oidc_proofing_views.route('/proofing', methods=['GET'])
@MarshalWith(schemas.NonceResponseSchema)
@require_user
def get_seleg_state(user):
    current_app.logger.debug('Getting state for user {!s}.'.format(user))
    try:
        proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn)
    except DocumentDoesNotExist:
        return {}
    # Return nonce and nonce as qr code
    current_app.logger.debug('Returning nonce for user {!s}'.format(user))
    buf = StringIO()
    # The "1" below denotes the version of the data exchanged, right now only version 1 is supported.
    qr_code = '1' + json.dumps({'nonce': proofing_state.nonce, 'token': proofing_state.token})
    qrcode.make(qr_code).save(buf)
    qr_b64 = buf.getvalue().encode('base64')
    return {
        'qr_code': qr_code,
        'qr_img': 'data:image/png;base64, {!s}'.format(qr_b64),
    }


@oidc_proofing_views.route('/proofing', methods=['POST'])
@UnmarshalWith(schemas.OidcProofingRequestSchema)
@MarshalWith(schemas.NonceResponseSchema)
@require_user
def seleg_proofing(user, nin):
    # For now a user can just have one verified NIN
    if user.nins.primary.verified is not None:
        return {'_status': 'error', 'error': 'User is already verified'}
    # A user can not verify new nin if one already exists
    if len(user.nins.to_list()) > 0 and any(item for item in user.nins.to_list() if item.number != nin):
        return {'_status': 'error', 'error': 'Another nin is already registered for this user'}

    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)
    if not proofing_state:
        current_app.logger.debug('No proofing state found for user {!s}. Initializing new proofing flow.'.format(user))
        proofing_state = helpers.create_proofing_state(user, nin)
        helpers.add_nin_to_user(user, proofing_state)

        # Initiate authn request
        try:
            redirect_url = url_for('oidc_proofing.authorization_response', _external=True)
            claims_request = ClaimsRequest(userinfo=Claims(identity=None))
            success = helpers.do_authn_request(proofing_state, claims_request, redirect_url)
            if not success:
                return {'_status': 'error', 'error': 'Temporary technical problems'}
        except requests.exceptions.ConnectionError as e:
            msg = 'No connection to authorization endpoint: {!s}'.format(e)
            current_app.logger.error(msg)
            return {'_status': 'error', 'error': msg}

        # If authentication request went well save user state
        current_app.proofing_statedb.save(proofing_state)
        current_app.logger.debug('Proofing state {!s} for user {!s} saved'.format(proofing_state.state, user))

    return get_seleg_state(user)


@oidc_proofing_views.route('/freja/proofing', methods=['GET'])
@MarshalWith(schemas.OpaqueResponseSchema)
@require_user
def get_freja_state(user):
    current_app.logger.debug('Getting state for user {!s}.'.format(user))
    try:
        proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn)
    except DocumentDoesNotExist:
        return {}
    # Return nonce and token
    current_app.logger.debug('Returning nonce and token for user {!s}'.format(user))
    # The "1" below denotes the version of the data exchanged, right now only version 1 is supported.
    opaque_data = '1' + json.dumps({'nonce': proofing_state.nonce, 'token': proofing_state.token})
    return {
        'opaque': opaque_data
    }


@oidc_proofing_views.route('/freja/proofing', methods=['POST'])
@UnmarshalWith(schemas.OidcProofingRequestSchema)
@MarshalWith(schemas.OpaqueResponseSchema)
@require_user
def freja_proofing(user, nin):

    # For now a user can just have one verified NIN
    if user.nins.primary.verified is not None:
        return {'_status': 'error', 'error': 'User is already verified'}
    # A user can not verify new nin if one already exists
    if len(user.nins.to_list()) > 0 and any(item for item in user.nins.to_list() if item.number != nin):
        return {'_status': 'error', 'error': 'Another nin is already registered for this user'}

    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)
    if not proofing_state:
        current_app.logger.debug('No proofing state found for user {!s}. Initializing new proofing flow.'.format(user))
        proofing_state = helpers.create_proofing_state(user, nin)
        helpers.add_nin_to_user(user, proofing_state)

        # Initiate authn request
        try:
            redirect_url = url_for('oidc_proofing.authorization_response', _external=True)
            claims_request = ClaimsRequest(userinfo=Claims(freja_proofing=None))
            success = helpers.do_authn_request(proofing_state, claims_request, redirect_url)
            if not success:
                return {'_status': 'error', 'error': 'Temporary technical problems'}
        except requests.exceptions.ConnectionError as e:
            msg = 'No connection to authorization endpoint: {!s}'.format(e)
            current_app.logger.error(msg)
            return {'_status': 'error', 'error': msg}

        # If authentication request went well save user state
        current_app.proofing_statedb.save(proofing_state)
        current_app.logger.debug('Proofing state {!s} for user {!s} saved'.format(proofing_state.state, user))

    return get_freja_state(user)
