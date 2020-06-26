# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, redirect, request, url_for
from oic.oic.message import AuthorizationResponse, Claims, ClaimsRequest
from six.moves.urllib_parse import urlencode

from eduid_common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid_common.api.messages import CommonMsg, redirect_with_msg
from eduid_common.api.schemas.csrf import CSRFRequest
from eduid_common.api.utils import get_unique_hash, save_and_sync_user
from eduid_userdb.logs import OrcidProofing
from eduid_userdb.orcid import OidcAuthorization, OidcIdToken, Orcid
from eduid_userdb.proofing import OrcidProofingState, ProofingUser

from eduid_webapp.orcid.app import current_orcid_app as current_app
from eduid_webapp.orcid.helpers import OrcidMsg
from eduid_webapp.orcid.schemas import OrcidResponseSchema

__author__ = 'lundberg'

orcid_views = Blueprint('orcid', __name__, url_prefix='', template_folder='templates')


@orcid_views.route('/authorize', methods=['GET'])
@require_user
def authorize(user):
    if user.orcid is None:
        proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)
        if not proofing_state:
            current_app.logger.debug(
                'No proofing state found for user {!s}. Initializing new proofing state.'.format(user)
            )
            proofing_state = OrcidProofingState(
                id=None, modified_ts=None, eppn=user.eppn, state=get_unique_hash(), nonce=get_unique_hash()
            )
            current_app.proofing_statedb.save(proofing_state)

        claims_request = ClaimsRequest(userinfo=Claims(id=None))
        oidc_args = {
            'client_id': current_app.oidc_client.client_id,
            'response_type': 'code',
            'scope': 'openid',
            'claims': claims_request.to_json(),
            'redirect_uri': url_for('orcid.authorization_response', _external=True),
            'state': proofing_state.state,
            'nonce': proofing_state.nonce,
        }
        authorization_url = '{}?{}'.format(current_app.oidc_client.authorization_endpoint, urlencode(oidc_args))
        current_app.logger.debug('Authorization url: {!s}'.format(authorization_url))
        current_app.stats.count(name='authn_request')
        return redirect(authorization_url)
    # Orcid already connected to user
    redirect_url = current_app.config.orcid_verify_redirect_url
    return redirect_with_msg(redirect_url, OrcidMsg.already_connected)


@orcid_views.route('/authorization-response', methods=['GET'])
@require_user
def authorization_response(user):
    # Redirect url for user feedback
    redirect_url = current_app.config.orcid_verify_redirect_url

    current_app.stats.count(name='authn_response')

    # parse authentication response
    query_string = request.query_string.decode('utf-8')
    current_app.logger.debug('query_string: {!s}'.format(query_string))

    authn_resp = current_app.oidc_client.parse_response(AuthorizationResponse, info=query_string, sformat='urlencoded')
    current_app.logger.debug('Authorization response received: {!s}'.format(authn_resp))

    if authn_resp.get('error'):
        current_app.logger.error(
            'AuthorizationError from {}: {} - {} ({})'.format(
                request.host, authn_resp['error'], authn_resp.get('error_message'), authn_resp.get('error_description')
            )
        )
        return redirect_with_msg(redirect_url, OrcidMsg.authz_error)

    user_oidc_state = authn_resp['state']
    proofing_state = current_app.proofing_statedb.get_state_by_oidc_state(user_oidc_state, raise_on_missing=False)
    if not proofing_state:
        current_app.logger.error('The \'state\' parameter ({!s}) does not match a user state.'.format(user_oidc_state))
        return redirect_with_msg(redirect_url, OrcidMsg.no_state)

    # do token request
    args = {
        'code': authn_resp['code'],
        'redirect_uri': url_for('orcid.authorization_response', _external=True),
    }
    current_app.logger.debug('Trying to do token request: {!s}'.format(args))
    token_resp = current_app.oidc_client.do_access_token_request(
        scope='openid', state=authn_resp['state'], request_args=args, authn_method='client_secret_basic'
    )
    current_app.logger.debug('token response received: {!s}'.format(token_resp))
    id_token = token_resp['id_token']
    if id_token['nonce'] != proofing_state.nonce:
        current_app.logger.error('The \'nonce\' parameter does not match for user')
        return redirect_with_msg(redirect_url, OrcidMsg.unknown_nonce)

    current_app.logger.info('ORCID authorized for user')

    # do userinfo request
    current_app.logger.debug('Trying to do userinfo request:')
    userinfo = current_app.oidc_client.do_user_info_request(
        method=current_app.config.userinfo_endpoint_method, state=authn_resp['state']
    )
    current_app.logger.debug('userinfo received: {!s}'.format(userinfo))
    if userinfo['sub'] != id_token['sub']:
        current_app.logger.error(
            'The \'sub\' of userinfo does not match \'sub\' of ID Token for user {!s}.'.format(proofing_state.eppn)
        )
        return redirect_with_msg(redirect_url, OrcidMsg.sub_mismatch)

    # Save orcid and oidc data to user
    current_app.logger.info('Saving ORCID data for user')
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    oidc_id_token = OidcIdToken.from_dict(
        dict(
            iss=id_token['iss'],
            sub=id_token['sub'],
            aud=id_token['aud'],
            exp=id_token['exp'],
            iat=id_token['iat'],
            nonce=id_token['nonce'],
            auth_time=id_token['auth_time'],
            created_by='orcid',
        )
    )
    oidc_authz = OidcAuthorization.from_dict(
        dict(
            access_token=token_resp['access_token'],
            token_type=token_resp['token_type'],
            id_token=oidc_id_token,
            expires_in=token_resp['expires_in'],
            refresh_token=token_resp['refresh_token'],
            created_by='orcid',
        )
    )
    orcid_element = Orcid.from_dict(
        dict(
            id=userinfo['id'],
            name=userinfo['name'],
            given_name=userinfo['given_name'],
            family_name=userinfo['family_name'],
            verified=True,
            oidc_authz=oidc_authz,
            created_by='orcid',
        )
    )
    orcid_proofing = OrcidProofing(
        proofing_user,
        created_by='orcid',
        orcid=orcid_element.id,
        issuer=orcid_element.oidc_authz.id_token.iss,
        audience=orcid_element.oidc_authz.id_token.aud,
        proofing_method='oidc',
        proofing_version='2018v1',
    )

    if current_app.proofing_log.save(orcid_proofing):
        current_app.logger.info('ORCID proofing data saved to log')
        proofing_user.orcid = orcid_element
        save_and_sync_user(proofing_user)
        current_app.logger.info('ORCID proofing data saved to user')
        message_args = dict(msg=OrcidMsg.authz_success, error=False)
    else:
        current_app.logger.info('ORCID proofing data NOT saved, failed to save proofing log')
        message_args = dict(msg=CommonMsg.temp_problem)

    # Clean up
    current_app.logger.info('Removing proofing state')
    current_app.proofing_statedb.remove_state(proofing_state)
    return redirect_with_msg(redirect_url, **message_args)


@orcid_views.route('/', methods=['GET'])
@MarshalWith(OrcidResponseSchema)
@require_user
def get_orcid(user):
    return user.to_dict()


@orcid_views.route('/remove', methods=['POST'])
@MarshalWith(OrcidResponseSchema)
@UnmarshalWith(CSRFRequest)
@require_user
def remove_orcid(user):
    current_app.logger.info('Removing ORCID data for user')
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    proofing_user.orcid = None
    save_and_sync_user(proofing_user)
    current_app.logger.info('ORCID data removed for user')
    return proofing_user.to_dict()
