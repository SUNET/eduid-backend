# -*- coding: utf-8 -*-
from urllib.parse import urlencode

from flask import Blueprint, Response, redirect, request, url_for
from oic.oic import ClaimsRequest, Claims, AuthorizationResponse
from werkzeug import Response as WerkzeugResponse

from eduid.common.utils import urlappend
from eduid.userdb.proofing import ProofingUser
from eduid.webapp.common.api.decorators import MarshalWith, require_user
from eduid.webapp.common.api.messages import error_response, success_response, FluxData
from eduid.webapp.common.api.utils import get_unique_hash
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import OIDCData, OIDCResult, OIDCState
from eduid.webapp.svipe_id.app import current_svipe_id_app as current_app
from eduid.webapp.svipe_id.helpers import SvipeIDMsg
from eduid.webapp.svipe_id.schemas import SvipeIDResultResponseSchema

__author__ = 'lundberg'


svipe_id_views = Blueprint('svipe_id', __name__, url_prefix='', template_folder='templates')


@svipe_id_views.route('/proofing', methods=['GET'])
@require_user
def proofing(user) -> WerkzeugResponse:
    state = get_unique_hash()
    nonce = get_unique_hash()
    session.svipe_id.oidc_states[OIDCState(state)] = OIDCData(nonce=nonce)

    claims_request = ClaimsRequest(
        svipeid=Claims(acr={'essential': True}),
        document_type=Claims(acr={'essential': True}),
        acm=Claims(values=['biometric_present']),
    )
    oidc_args = {
        'client_id': current_app.oidc_client.client_id,
        'response_type': 'code',
        'scope': 'openid',
        'claims': claims_request.to_json(),
        'redirect_uri': url_for('svipe_id.proofing_callback', _external=True),
        'state': state,
        'nonce': nonce,
    }
    authorization_url = f'{current_app.oidc_client.authorization_endpoint}?{urlencode(oidc_args)}'
    current_app.logger.debug('Authorization url: {!s}'.format(authorization_url))
    current_app.stats.count(name='proofing_authn_request')
    return redirect(authorization_url)


@svipe_id_views.route('/proofing-callback', methods=['GET'])
@require_user
def proofing_callback(user):
    # Redirect url for user feedback
    redirect_url = current_app.conf.proofing_redirect_url

    current_app.stats.count(name='proofing_authn_response')

    # parse authentication response
    current_app.logger.debug(f'request.args: {request.args}')
    authn_resp = current_app.oidc_client.parse_response(AuthorizationResponse, info=request.args, sformat='dict')
    current_app.logger.debug(f'Authorization response received: {authn_resp}')

    oidc_state = authn_resp['state']
    # TODO: Investigate
    current_app.oidc_client.grant[oidc_state] = current_app.oidc_client.grant_class(
        resp=authn_resp
    )  # why do I have to do this? this should be done in parse_response above

    if oidc_state not in session.svipe_id.oidc_states:
        session.svipe_id.oidc_states[oidc_state] = OIDCData(
            result=OIDCResult(message=SvipeIDMsg.no_state.value, error=True)
        )
        return redirect(f'{urlappend(redirect_url, oidc_state)}')

    if authn_resp.get('error'):
        current_app.logger.error(
            'AuthorizationError from {}: {} - {} ({})'.format(
                request.host, authn_resp['error'], authn_resp.get('error_message'), authn_resp.get('error_description')
            )
        )
        session.svipe_id.oidc_states[oidc_state].result = OIDCResult(message=SvipeIDMsg.authz_error.value, error=True)
        return redirect(f'{urlappend(redirect_url, oidc_state)}')

    # do token request
    oidc_code = authn_resp['code']
    token_req_args = {
        'code': oidc_code,
        'redirect_uri': url_for('svipe_id.proofing_callback', _external=True),
    }
    current_app.logger.debug(f'Trying to do token request: {token_req_args}')
    token_resp = current_app.oidc_client.do_access_token_request(
        scope='openid', state=oidc_state, request_args=token_req_args, authn_method='client_secret_basic'
    )
    current_app.logger.debug(f'token response received: {token_resp}')
    id_token = token_resp['id_token']
    if id_token['nonce'] != session.svipe_id.oidc_states[oidc_state].nonce:
        current_app.logger.error('The \'nonce\' parameter does not match for user')
        session.svipe_id.oidc_states[oidc_state].result = OIDCResult(message=SvipeIDMsg.unknown_nonce.value, error=True)
        return redirect(f'{urlappend(redirect_url, oidc_state)}')

    # do userinfo request
    current_app.logger.debug('Trying to do userinfo request:')
    # userinfo = current_app.oidc_client.do_user_info_request(
    #    method=current_app.conf.userinfo_endpoint_method, state=oidc_state
    # )
    userinfo = current_app.oidc_client.do_user_info_request(state=oidc_state)
    current_app.logger.debug(f'userinfo received: {userinfo}')
    if userinfo['sub'] != id_token['sub']:
        current_app.logger.error('The \'sub\' of userinfo does not match \'sub\' of ID Token')
        session.svipe_id.oidc_states[oidc_state].result = OIDCResult(message=SvipeIDMsg.sub_mismatch.value, error=True)
        return redirect(f'{urlappend(redirect_url, oidc_state)}')

    # create proofing log and verify users identity
    current_app.logger.info('Saving data for user')
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

    # if not current_app.proofing_log.save(svipe_id_proofing):
    #    current_app.logger.error('proofing data NOT saved, failed to save proofing log')
    #    session.svipe_id.oidc_states[oidc_state].result = OIDCResult(message=CommonMsg.temp_problem.value, error=True)
    #    return redirect(f'{urlappend(redirect_url, oidc_state)}')

    current_app.logger.info('proofing data saved to log')
    # proofing_user.orcid = orcid_element
    # save_and_sync_user(proofing_user)
    current_app.logger.info('proofing data saved to user')

    session.svipe_id.oidc_states[oidc_state].result = OIDCResult(message=SvipeIDMsg.identity_proofing_success.value)
    current_app.oidc_client.do_end_session_request(state=oidc_state)
    return redirect(f'{urlappend(redirect_url, oidc_state)}')


@svipe_id_views.route('/proofing-result/<oidc_state>', methods=['GET'])
@MarshalWith(SvipeIDResultResponseSchema)
@require_user
def proofing_result(user, oidc_state) -> FluxData:
    result = session.svipe_id.oidc_states.get(oidc_state)
    if result is None:
        return error_response(message=SvipeIDMsg.no_state)
    return success_response(payload=result.dict())
