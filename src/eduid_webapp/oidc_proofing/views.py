# -*- coding: utf-8 -*-
from __future__ import absolute_import

import base64
import binascii

import qrcode
import qrcode.image.svg
import requests
from flask import Blueprint, make_response, request, url_for
from jose import jws as jose
from oic.oic.message import AuthorizationResponse, Claims, ClaimsRequest
from six import BytesIO

from eduid_common.api.decorators import MarshalWith, UnmarshalWith, can_verify_identity, require_user
from eduid_common.api.exceptions import TaskFailed
from eduid_common.api.helpers import add_nin_to_user
from eduid_common.api.messages import CommonMsg, error_response
from eduid_userdb.exceptions import DocumentDoesNotExist
from eduid_userdb.proofing import ProofingUser
from eduid_userdb.util import UTC

from eduid_webapp.oidc_proofing import helpers, schemas
from eduid_webapp.oidc_proofing.app import current_oidcp_app as current_app
from eduid_webapp.oidc_proofing.helpers import OIDCMsg

__author__ = 'lundberg'

"""
OIDC code very inspired by https://github.com/its-dirg/Flask-pyoidc
"""

oidc_proofing_views = Blueprint('oidc_proofing', __name__, url_prefix='', template_folder='templates')


@oidc_proofing_views.route('/authorization-response')
def authorization_response():
    # parse authentication response
    query_string = request.query_string.decode('utf-8')
    current_app.logger.debug('query_string: {!s}'.format(query_string))
    authn_resp = current_app.oidc_client.parse_response(AuthorizationResponse, info=query_string, sformat='urlencoded')
    current_app.logger.debug('Authorization response received: {!s}'.format(authn_resp))

    if authn_resp.get('error'):
        current_app.logger.error(
            'AuthorizationError from {}: {} - {} ({})'.format(
                request.host, authn_resp['error'], authn_resp.get('error_message'), authn_resp.get('error_uri')
            )
        )
        current_app.stats.count(name='authn_response_op_error')
        return make_response('OK', 200)

    user_oidc_state = authn_resp['state']
    proofing_state = current_app.proofing_statedb.get_state_by_oidc_state(user_oidc_state)
    if not proofing_state:
        msg = 'The \'state\' parameter ({!s}) does not match a user state.'.format(user_oidc_state)
        current_app.logger.error(msg)
        current_app.stats.count(name='authn_response_proofing_state_missing')
        return make_response('OK', 200)
    current_app.logger.debug(
        'Proofing state {!s} for user {!s} found'.format(proofing_state.state, proofing_state.eppn)
    )

    # Check if the token from the authn response matches the token we created when making the auth request
    authorization_header = request.headers.get('Authorization')
    if authorization_header != 'Bearer {}'.format(proofing_state.token):
        current_app.logger.error(
            'The authorization token ({!s}) did not match the expected'.format(authorization_header)
        )
        current_app.stats.count(name='authn_response_authn_failure')
        return make_response('FORBIDDEN', 403)

    # TODO: We should save the auth response code to the proofing state to be able to continue a failed attempt
    # do token request
    args = {'code': authn_resp['code'], 'redirect_uri': url_for('oidc_proofing.authorization_response', _external=True)}
    current_app.logger.debug('Trying to do token request: {!s}'.format(args))
    # TODO: What should be saved from the token response and where?
    token_resp = current_app.oidc_client.do_access_token_request(
        scope='openid', state=authn_resp['state'], request_args=args, authn_method='client_secret_basic'
    )
    current_app.logger.debug('token response received: {!s}'.format(token_resp))
    id_token = token_resp['id_token']
    if id_token['nonce'] != proofing_state.nonce:
        current_app.logger.error('The \'nonce\' parameter does not match for user {!s}.'.format(proofing_state.eppn))
        current_app.stats.count(name='authn_response_token_request_failure')
        return make_response('OK', 200)
    current_app.stats.count(name='authn_response_token_request_success')

    # do userinfo request
    current_app.logger.debug('Trying to do userinfo request:')
    # TODO: Do we need to save anything else from the userinfo response
    userinfo = current_app.oidc_client.do_user_info_request(
        method=current_app.config.userinfo_endpoint_method, state=authn_resp['state']
    )
    current_app.logger.debug('userinfo received: {!s}'.format(userinfo))
    if userinfo['sub'] != id_token['sub']:
        current_app.logger.error(
            'The \'sub\' of userinfo does not match \'sub\' of ID Token for user {!s}.'.format(proofing_state.eppn)
        )
        current_app.stats.count(name='authn_response_userinfo_request_failure')
        return make_response('OK', 200)
    current_app.stats.count(name='authn_response_userinfo_request_success')

    # TODO: Break out in parts to be able to continue the proofing process after a successful authorization response
    # TODO: even if the token request, userinfo request or something internal fails
    am_user = current_app.central_userdb.get_user_by_eppn(proofing_state.eppn)
    user = ProofingUser.from_user(am_user, current_app.private_userdb)

    try:
        # Handle userinfo differently depending on data in userinfo
        if userinfo.get('identity'):
            current_app.logger.info('Handling userinfo as generic seleg vetting for user {}'.format(user))
            current_app.stats.count(name='seleg.authn_response_received')
            helpers.handle_seleg_userinfo(user, proofing_state, userinfo)
        elif userinfo.get('results'):
            current_app.logger.info('Handling userinfo as freja vetting for user {}'.format(user))
            current_app.stats.count(name='freja.authn_response_received')
            helpers.handle_freja_eid_userinfo(user, proofing_state, userinfo)
    except (TaskFailed, KeyError) as e:
        current_app.logger.error('Failed to handle userinfo for user {}'.format(user))
        current_app.logger.error('Exception: {}'.format(e))
        current_app.stats.count(name='authn_response_handling_failure')
    finally:
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
        expire_time = current_app.config.seleg_expire_time_hours
        if helpers.is_proofing_state_expired(proofing_state, expire_time):
            current_app.proofing_statedb.remove_state(proofing_state)
            current_app.stats.count(name='seleg.proofing_state_expired')
            raise DocumentDoesNotExist(reason='seleg proofing state expired')
    except DocumentDoesNotExist:
        return {}
    # Return nonce and nonce as qr code
    current_app.logger.debug('Returning nonce for user {!s}'.format(user))
    current_app.stats.count(name='seleg.proofing_state_returned')
    buf = BytesIO()
    qr_code = helpers.create_opaque_data(proofing_state.nonce, proofing_state.token)
    qrcode.make(qr_code).save(buf)
    qr_b64 = base64.b64encode(buf.getvalue())
    return {
        'qr_code': qr_code,
        'qr_img': 'data:image/png;base64, {!s}'.format(qr_b64),
    }


@oidc_proofing_views.route('/proofing', methods=['POST'])
@UnmarshalWith(schemas.OidcProofingRequestSchema)
@MarshalWith(schemas.NonceResponseSchema)
@can_verify_identity
@require_user
def seleg_proofing(user, nin):
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)
    if not proofing_state:
        current_app.logger.debug('No proofing state found for user {!s}. Initializing new proofing flow.'.format(user))
        proofing_state = helpers.create_proofing_state(user, nin)

        # Initiate authn request
        try:
            redirect_url = url_for('oidc_proofing.authorization_response', _external=True)
            claims_request = ClaimsRequest(userinfo=Claims(identity=None, vetting_time=None, metadata=None))
            success = helpers.do_authn_request(proofing_state, claims_request, redirect_url)
            if not success:
                current_app.stats.count(name='seleg.authn_request_op_error')
                return error_response(message=CommonMsg.temp_problem)
        except requests.exceptions.ConnectionError as e:
            current_app.logger.error('No connection to authorization endpoint: {!s}'.format(e))
            return error_response(message=OIDCMsg.no_conn)

        # If authentication request went well save user state
        current_app.stats.count(name='seleg.authn_request_success')
        current_app.proofing_statedb.save(proofing_state)
        current_app.logger.debug('Proofing state {!s} for user {!s} saved'.format(proofing_state.state, user))
    # Add the nin used to initiate the proofing state to the user
    # NOOP if the user already have the nin
    add_nin_to_user(user, proofing_state)

    return get_seleg_state()


@oidc_proofing_views.route('/freja/proofing', methods=['GET'])
@MarshalWith(schemas.FrejaResponseSchema)
@require_user
def get_freja_state(user):
    current_app.logger.debug('Getting state for user {!s}.'.format(user))
    try:
        proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn)
        expire_time = current_app.config.freja_expire_time_hours
        if helpers.is_proofing_state_expired(proofing_state, expire_time):
            current_app.proofing_statedb.remove_state(proofing_state)
            current_app.stats.count(name='freja.proofing_state_expired')
            raise DocumentDoesNotExist(reason='freja proofing state expired')
    except DocumentDoesNotExist:
        return {}
    # Return request data
    current_app.logger.debug('Returning request data for user {!s}'.format(user))
    current_app.stats.count(name='freja.proofing_state_returned')
    opaque_data = helpers.create_opaque_data(proofing_state.nonce, proofing_state.token)
    valid_until = helpers.get_proofing_state_valid_until(proofing_state, expire_time)
    request_data = {
        "iarp": current_app.config.freja_iarp,
        "exp": int(valid_until.astimezone(UTC()).strftime('%s')) * 1000,  # Milliseconds since 1970 in UTC
        "proto": current_app.config.freja_response_protocol,
        "opaque": opaque_data,
    }

    jwk = binascii.unhexlify(current_app.config.freja_jwk_secret)
    jws_header = {
        'alg': current_app.config.freja_jws_algorithm,
        'kid': current_app.config.freja_jws_key_id,
    }
    jws = jose.sign(request_data, jwk, headers=jws_header, algorithm=current_app.config.freja_jws_algorithm)
    return {'iaRequestData': jws}


@oidc_proofing_views.route('/freja/proofing', methods=['POST'])
@UnmarshalWith(schemas.OidcProofingRequestSchema)
@MarshalWith(schemas.FrejaResponseSchema)
@can_verify_identity
@require_user
def freja_proofing(user, nin):
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)
    if not proofing_state:
        current_app.logger.debug('No proofing state found for user {!s}. Initializing new proofing flow.'.format(user))
        proofing_state = helpers.create_proofing_state(user, nin)

        # Initiate authn request
        try:
            redirect_url = url_for('oidc_proofing.authorization_response', _external=True)
            claims_request = ClaimsRequest(userinfo=Claims(results=None))
            success = helpers.do_authn_request(proofing_state, claims_request, redirect_url)
            if not success:
                current_app.stats.count(name='freja.authn_request_op_error')
                return error_response(message=CommonMsg.temp_problem)
        except requests.exceptions.ConnectionError as e:
            current_app.logger.error('No connection to authorization endpoint: {!s}'.format(e))
            return error_response(message=OIDCMsg.no_conn)

        # If authentication request went well save user state
        current_app.stats.count(name='freja.authn_request_success')
        current_app.proofing_statedb.save(proofing_state)
        current_app.logger.debug('Proofing state {!s} for user {!s} saved'.format(proofing_state.state, user))
    # Add the nin used to initiate the proofing state to the user
    # NOOP if the user already have the nin
    add_nin_to_user(user, proofing_state)

    return get_freja_state()
