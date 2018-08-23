# -*- coding: utf-8 -*-

from __future__ import absolute_import

try:
    # Python 2
    import urlparse
except ImportError:
    # Python 3
    from urllib import parse as urlparse
from urllib import urlencode

from flask import Blueprint, current_app, request, redirect, url_for, jsonify
from eduid_common.api.decorators import require_user
from eduid_common.api.utils import get_unique_hash, urlappend, save_and_sync_user
from eduid_userdb.proofing import ProofingUser, OrcidProofingState
from eduid_userdb.orcid import Orcid, OidcAuthorization, OidcIdToken
from eduid_userdb.logs import OrcidProofing

from oic.oic.message import AuthorizationResponse


__author__ = 'lundberg'

orcid_views = Blueprint('orcid', __name__, url_prefix='', template_folder='templates')


@orcid_views.route('/authorization-response', methods=['GET'])
@require_user
def authorization_response(user):
    # Redirect url for user feedback
    url = urlappend(current_app.config['DASHBOARD_URL'], 'personaldata')
    scheme, netloc, path, query_string, fragment = urlparse.urlsplit(url)

    # parse authentication response
    query_string = request.query_string.decode('utf-8')
    current_app.logger.debug('query_string: {!s}'.format(query_string))
    authn_resp = current_app.oidc_client.parse_response(AuthorizationResponse, info=query_string,
                                                        sformat='urlencoded')
    current_app.logger.debug('Authorization response received: {!s}'.format(authn_resp))

    user_oidc_state = authn_resp['state']
    proofing_state = current_app.proofing_statedb.get_state_by_oidc_state(user_oidc_state, raise_on_missing=False)
    if not proofing_state:
        current_app.logger.error('The \'state\' parameter ({!s}) does not match a user state.'.format(user_oidc_state))
        new_query_string = urlencode({'msg': ':ERROR:orc.unknown_state'})
        url = urlparse.urlunsplit((scheme, netloc, path, new_query_string, fragment))
        return redirect(url)

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
        url = urlparse.urlunsplit((scheme, netloc, path, new_query_string, fragment))
        return redirect(url)
    current_app.logger.info('ORCID authorized for user')

    # Save orcid and oidc data to user
    current_app.logger.info('Saving ORCID data for user')
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    oidc_id_token = OidcIdToken(iss=id_token['iss'], sub=id_token['sub'], aud=id_token['aud'], exp=id_token['exp'],
                                iat=id_token['iat'], nonce=id_token['nonce'], auth_time=id_token['auth_time'],
                                application='orcid')
    oidc_authz = OidcAuthorization(access_token=token_resp['access_token'], token_type=token_resp['token_type'],
                                   id_token=oidc_id_token, expires_in=token_resp['expires_in'],
                                   refresh_token=token_resp['refresh_token'], application='orcid')
    orcid_element = Orcid(id=token_resp['orcid'], verified=True, oidc_authz=oidc_authz, application='orcid')
    orcid_proofing = OrcidProofing(proofing_user, created_by='orcid', orcid=orcid_element.id,
                                   issuer=orcid_element.oidc_authz.id_token.iss,
                                   audience=orcid_element.oidc_authz.id_token.aud, proofing_method='oidc',
                                   proofing_version='2018v1')
    if current_app.proofing_log.save(orcid_proofing):
        current_app.logger.info('ORCID proofing data saved to log')
        proofing_user.orcid = orcid_element
        save_and_sync_user(proofing_user)

    # Clean up
    current_app.logger.info('Removing proofing state for user {}'.format(proofing_state.eppn))
    current_app.proofing_statedb.remove_state(proofing_state)
    new_query_string = urlencode({'msg': 'orc.authorization-success'})
    url = urlparse.urlunsplit((scheme, netloc, path, new_query_string, fragment))
    return redirect(url)


@orcid_views.route('/', methods=['GET'])
@MarshalWith(OrcidResponseSchema)
@require_user
def get_orcid(user):
    return user.to_dict()
