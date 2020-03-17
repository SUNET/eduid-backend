# -*- coding: utf-8 -*-

from __future__ import absolute_import

from six.moves.urllib_parse import urlencode, urlsplit, urlunsplit

from flask import Blueprint, request, redirect, url_for
from oic.oic.message import AuthorizationResponse, ClaimsRequest, Claims

from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import get_unique_hash, save_and_sync_user
from eduid_common.api.schemas.csrf import CSRFRequest
from eduid_userdb.proofing import ProofingUser, OrcidProofingState
from eduid_userdb.orcid import Orcid, OidcAuthorization, OidcIdToken
from eduid_userdb.logs import OrcidProofing
from eduid_webapp.orcid.schemas import OrcidResponseSchema
from eduid_webapp.orcid.app import current_orcid_app as current_app


__author__ = 'lundberg'

orcid_views = Blueprint('orcid', __name__, url_prefix='', template_folder='templates')


@orcid_views.route('/authorize', methods=['GET'])
@require_user
def authorize(user):
    if user.orcid is None:
        proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn, raise_on_missing=False)
        if not proofing_state:
            current_app.logger.debug('No proofing state found for user {!s}. Initializing new proofing state.'.format(
                user))
            proofing_state = OrcidProofingState(id=None, modified_ts=None,
                                                eppn=user.eppn, state=get_unique_hash(), nonce=get_unique_hash())
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
    scheme, netloc, path, query_string, fragment = urlsplit(redirect_url)
    new_query_string = urlencode({'msg': ':ERROR:orc.already_connected'})
    redirect_url = urlunsplit((scheme, netloc, path, new_query_string, fragment))
    return redirect(redirect_url)


@orcid_views.route('/authorization-response', methods=['GET'])
@require_user
def authorization_response(user):
    # Redirect url for user feedback
    redirect_url = current_app.config.orcid_verify_redirect_url
    scheme, netloc, path, query_string, fragment = urlsplit(redirect_url)

    current_app.stats.count(name='authn_response')

    # parse authentication response
    query_string = request.query_string.decode('utf-8')
    current_app.logger.debug('query_string: {!s}'.format(query_string))

    authn_resp = current_app.oidc_client.parse_response(AuthorizationResponse, info=query_string,
                                                        sformat='urlencoded')
    current_app.logger.debug('Authorization response received: {!s}'.format(authn_resp))

    if authn_resp.get('error'):
        current_app.logger.error('AuthorizationError from {}: {} - {} ({})'.format(request.host, authn_resp['error'],
                                                                                   authn_resp.get('error_message'),
                                                                                   authn_resp.get('error_description')))
        new_query_string = urlencode({'msg': ':ERROR:orc.authorization_fail'})
        redirect_url = urlunsplit((scheme, netloc, path, new_query_string, fragment))
        return redirect(redirect_url)

    user_oidc_state = authn_resp['state']
    proofing_state = current_app.proofing_statedb.get_state_by_oidc_state(user_oidc_state, raise_on_missing=False)
    if not proofing_state:
        current_app.logger.error('The \'state\' parameter ({!s}) does not match a user state.'.format(user_oidc_state))
        new_query_string = urlencode({'msg': ':ERROR:orc.unknown_state'})
        redirect_url = urlunsplit((scheme, netloc, path, new_query_string, fragment))
        return redirect(redirect_url)

    # do token request
    args = {
        'code': authn_resp['code'],
        'redirect_uri': url_for('orcid.authorization_response', _external=True),
    }
    current_app.logger.debug('Trying to do token request: {!s}'.format(args))
    token_resp = current_app.oidc_client.do_access_token_request(scope='openid', state=authn_resp['state'],
                                                                 request_args=args,
                                                                 authn_method='client_secret_basic')
    current_app.logger.debug('token response received: {!s}'.format(token_resp))
    id_token = token_resp['id_token']
    if id_token['nonce'] != proofing_state.nonce:
        current_app.logger.error('The \'nonce\' parameter does not match for user')
        new_query_string = urlencode({'msg': ':ERROR:orc.unknown_nonce'})
        redirect_url = urlunsplit((scheme, netloc, path, new_query_string, fragment))
        return redirect(redirect_url)
    current_app.logger.info('ORCID authorized for user')

    # do userinfo request
    current_app.logger.debug('Trying to do userinfo request:')
    userinfo = current_app.oidc_client.do_user_info_request(method=current_app.config.userinfo_endpoint_method,
                                                            state=authn_resp['state'])
    current_app.logger.debug('userinfo received: {!s}'.format(userinfo))
    if userinfo['sub'] != id_token['sub']:
        current_app.logger.error('The \'sub\' of userinfo does not match \'sub\' of ID Token for user {!s}.'.format(
            proofing_state.eppn))
        new_query_string = urlencode({'msg': ':ERROR:orc.sub_mismatch'})
        redirect_url = urlunsplit((scheme, netloc, path, new_query_string, fragment))
        return redirect(redirect_url)

    # Save orcid and oidc data to user
    current_app.logger.info('Saving ORCID data for user')
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    oidc_id_token = OidcIdToken(iss=id_token['iss'], sub=id_token['sub'], aud=id_token['aud'], exp=id_token['exp'],
                                iat=id_token['iat'], nonce=id_token['nonce'], auth_time=id_token['auth_time'],
                                application='orcid')
    oidc_authz = OidcAuthorization(access_token=token_resp['access_token'], token_type=token_resp['token_type'],
                                   id_token=oidc_id_token, expires_in=token_resp['expires_in'],
                                   refresh_token=token_resp['refresh_token'], application='orcid')
    orcid_element = Orcid(id=userinfo['id'], name=userinfo['name'], given_name=userinfo['given_name'],
                          family_name=userinfo['family_name'], verified=True, oidc_authz=oidc_authz,
                          application='orcid')
    orcid_proofing = OrcidProofing(proofing_user, created_by='orcid', orcid=orcid_element.id,
                                   issuer=orcid_element.oidc_authz.id_token.iss,
                                   audience=orcid_element.oidc_authz.id_token.aud, proofing_method='oidc',
                                   proofing_version='2018v1')

    if current_app.proofing_log.save(orcid_proofing):
        current_app.logger.info('ORCID proofing data saved to log')
        proofing_user.orcid = orcid_element
        save_and_sync_user(proofing_user)
        current_app.logger.info('ORCID proofing data saved to user')
        new_query_string = urlencode({'msg': 'orc.authorization_success'})
    else:
        current_app.logger.info('ORCID proofing data NOT saved, failed to save proofing log')
        new_query_string = urlencode({'msg': ':ERROR:Temporary technical problems'})

    # Clean up
    current_app.logger.info('Removing proofing state')
    current_app.proofing_statedb.remove_state(proofing_state)
    redirect_url = urlunsplit((scheme, netloc, path, new_query_string, fragment))
    return redirect(redirect_url)


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
