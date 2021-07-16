# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
from copy import deepcopy
from datetime import timedelta
from typing import Any, Dict, List, Optional, Sequence, Union

from bson import ObjectId
from flask import Blueprint, jsonify, redirect, request, url_for
from werkzeug.exceptions import BadRequest
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.misc.timeutil import utc_now
from eduid.userdb import ToUEvent
from eduid.userdb.actions.tou import ToUUser
from eduid.userdb.credentials import FidoCredential
from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.idp import IdPUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.exceptions import EduidForbidden, EduidTooManyRequests
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.models import FluxSuccessResponse
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.authn import fido_tokens
from eduid.webapp.common.session import session
from eduid.webapp.common.session.logindata import ExternalMfaData
from eduid.webapp.common.session.namespaces import MfaActionError, OnetimeCredential, OnetimeCredType, RequestRef
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance import get_requested_authn_context
from eduid.webapp.idp.helpers import IdPAction, IdPMsg
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.login import SSO, do_verify, get_ticket, login_next_step, show_login_page
from eduid.webapp.idp.logout import SLO

__author__ = 'ft'

from saml2 import BINDING_HTTP_POST

from eduid.webapp.idp.mischttp import parse_query_string, set_sso_cookie
from eduid.webapp.idp.schemas import (
    MfaAuthRequestSchema,
    MfaAuthResponseSchema,
    NextRequestSchema,
    NextResponseSchema,
    PwAuthRequestSchema,
    PwAuthResponseSchema,
    TouRequestSchema,
    TouResponseSchema,
)
from eduid.webapp.idp.service import SAMLQueryParams
from eduid.webapp.idp.sso_session import SSOSession

idp_views = Blueprint('idp', __name__, url_prefix='', template_folder='templates')


@idp_views.route('/', methods=['GET'])
def index() -> WerkzeugResponse:
    return redirect(current_app.conf.eduid_site_url)


@idp_views.route('/sso/post', methods=['POST'])
def sso_post() -> WerkzeugResponse:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- SingleSignOn POST: {request.path} ---')
    sso_session = current_app._lookup_sso_session()
    return SSO(sso_session).post()


@idp_views.route('/sso/redirect', methods=['GET'])
def sso_redirect() -> WerkzeugResponse:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- SingleSignOn REDIRECT: {request.path} ---')
    sso_session = current_app._lookup_sso_session()
    return SSO(sso_session).redirect()


@idp_views.route('/slo/post', methods=['POST'])
def slo_post() -> WerkzeugResponse:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- SingleLogOut POST: {request.path} ---')
    sso_session = current_app._lookup_sso_session()
    return SLO(sso_session).post()


@idp_views.route('/slo/soap', methods=['POST'])
def slo_soap() -> WerkzeugResponse:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- SingleLogOut SOAP: {request.path} ---')
    sso_session = current_app._lookup_sso_session()
    return SLO(sso_session).soap()


@idp_views.route('/slo/redirect', methods=['GET'])
def slo_redirect() -> WerkzeugResponse:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- SingleLogOut REDIRECT: {request.path} ---')
    slo_session = current_app._lookup_sso_session()
    return SLO(slo_session).redirect()


@idp_views.route('/verify', methods=['GET', 'POST'])
def verify() -> WerkzeugResponse:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f"--- Verify ({request.method}) ---")

    if request.method == 'GET':
        query = parse_query_string()
        if 'ref' not in query:
            raise BadRequest(f'Missing parameter - please re-initiate login')
        _info = SAMLQueryParams(request_ref=RequestRef(query['ref']))
        ticket = get_ticket(_info, None)
        if not ticket:
            raise BadRequest(f'Missing parameter - please re-initiate login')
        return show_login_page(ticket)

    if request.method == 'POST':
        return do_verify()

    raise BadRequest()


@idp_views.route('/next', methods=['POST'])
@UnmarshalWith(NextRequestSchema)
@MarshalWith(NextResponseSchema)
def next(ref: RequestRef) -> FluxData:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- Next ---')

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_available)

    _info = SAMLQueryParams(request_ref=ref)
    ticket = get_ticket(_info, None)
    if not ticket:
        return error_response(message=IdPMsg.bad_ref)

    sso_session = current_app._lookup_sso_session()

    _next = login_next_step(ticket, sso_session)
    current_app.logger.debug(f'Login Next: {_next}')

    if _next.message == IdPMsg.must_authenticate:
        return success_response(
            message=IdPMsg.must_authenticate,
            payload={'action': IdPAction.PWAUTH.value, 'target': url_for('idp.pw_auth')},
        )

    if _next.message == IdPMsg.mfa_required:
        return success_response(
            message=IdPMsg.mfa_required, payload={'action': IdPAction.MFA.value, 'target': url_for('idp.mfa_auth')}
        )

    if _next.message == IdPMsg.tou_required:
        return success_response(
            message=IdPMsg.tou_required, payload={'action': IdPAction.TOU.value, 'target': url_for('idp.tou')}
        )

    if _next.message == IdPMsg.user_terminated:
        return error_response(message=IdPMsg.user_terminated)

    if _next.message == IdPMsg.swamid_mfa_required:
        return error_response(message=IdPMsg.swamid_mfa_required)

    if _next.message == IdPMsg.proceed:
        if not sso_session:
            return error_response(message=IdPMsg.no_sso_session)

        user = current_app.userdb.lookup_user(sso_session.eppn)
        if not user:
            current_app.logger.error(f'User with eppn {sso_session.eppn} (from SSO session) not found')
            return error_response(message=IdPMsg.general_failure)

        sso = SSO(sso_session=sso_session)
        assert _next.authn_info  # please mypy
        saml_params = sso.get_response_params(_next.authn_info, ticket, user)
        if saml_params.binding != BINDING_HTTP_POST:
            current_app.logger.error(f'SAML response does not have binding HTTP_POST')
            return error_response(message=IdPMsg.general_failure)
        return success_response(
            message=IdPMsg.finished,
            payload={
                'action': IdPAction.FINISHED.value,
                'target': saml_params.url,
                'parameters': saml_params.post_params,
            },
        )

    return error_response(message=IdPMsg.not_implemented)


@idp_views.route('/pw_auth', methods=['POST'])
@UnmarshalWith(PwAuthRequestSchema)
@MarshalWith(PwAuthResponseSchema)
def pw_auth(ref: RequestRef, username: str, password: str) -> Union[FluxData, WerkzeugResponse]:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- Password authentication ({request.method}) ---')

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_available)

    _info = SAMLQueryParams(request_ref=ref)
    ticket = get_ticket(_info, None)
    if not ticket:
        return error_response(message=IdPMsg.bad_ref)

    if not username or not password:
        current_app.logger.debug(f'Credentials not supplied')
        return error_response(message=IdPMsg.wrong_credentials)

    try:
        pwauth = current_app.authn.password_authn(username, password)
    except EduidTooManyRequests:
        return error_response(message=IdPMsg.user_temporary_locked)
    except EduidForbidden as e:
        if e.args[0] == 'CREDENTIAL_EXPIRED':
            return error_response(message=IdPMsg.credential_expired)
        return error_response(message=IdPMsg.wrong_credentials)
    finally:
        del password  # keep out of any exception logs

    if not pwauth:
        current_app.logger.info(f'{ticket.request_ref}: Password authentication failed')
        return error_response(message=IdPMsg.wrong_credentials)

    # Create SSO session
    current_app.logger.debug(f'User {pwauth.user} authenticated OK (SAML id {repr(ticket.saml_req.request_id)})')
    _authn_credentials: List[AuthnData] = []
    if pwauth.authndata:
        _authn_credentials = [pwauth.authndata]
    _sso_session = SSOSession(
        authn_request_id=ticket.saml_req.request_id,
        authn_credentials=_authn_credentials,
        eppn=pwauth.user.eppn,
        expires_at=utc_now() + current_app.conf.sso_session_lifetime,
    )

    # This session contains information about the fact that the user was authenticated. It is
    # used to avoid requiring subsequent authentication for the same user during a limited
    # period of time, by storing the session-id in a browser cookie.
    current_app.sso_sessions.save(_sso_session)

    # INFO-Log the request id and the sso_session
    authn_ref = get_requested_authn_context(ticket)
    current_app.logger.debug(f'Authenticating with {repr(authn_ref)}')

    current_app.logger.info(
        f'{ticket.request_ref}: login sso_session={_sso_session.public_id}, authn={authn_ref}, user={pwauth.user}'
    )

    # Remember the password credential used for this particular request
    session.idp.log_credential_used(ticket.request_ref, pwauth.credential, pwauth.timestamp)

    # For debugging purposes, save the IdP SSO cookie value in the common session as well.
    # This is because we think we might have issues overwriting cookies in redirect responses.
    session.idp.sso_cookie_val = _sso_session.session_id

    _flux_response = FluxSuccessResponse(request, payload={'finished': True})
    resp = jsonify(PwAuthResponseSchema().dump(_flux_response.to_dict()))

    return set_sso_cookie(_sso_session.session_id, resp)


@idp_views.route('/mfa_auth', methods=['POST'])
@UnmarshalWith(MfaAuthRequestSchema)
@MarshalWith(MfaAuthResponseSchema)
def mfa_auth(ref: RequestRef, webauthn_response: Optional[Dict[str, str]] = None) -> FluxData:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- MFA authentication ({request.method}) ---')

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_available)

    _info = SAMLQueryParams(request_ref=ref)
    ticket = get_ticket(_info, None)
    if not ticket:
        return error_response(message=IdPMsg.bad_ref)

    sso_session = current_app._lookup_sso_session()
    if not sso_session:
        current_app.logger.error(f'MFA auth called without an SSO session')
        return error_response(message=IdPMsg.no_sso_session)

    user = current_app.userdb.lookup_user(sso_session.eppn)
    if not user:
        current_app.logger.error(f'User with eppn {sso_session.eppn} (from SSO session) not found')
        return error_response(message=IdPMsg.general_failure)

    # Clear mfa_action from session, so that we know if the user did external MFA
    # Yes - this should be done even if the user has FIDO credentials because the user might
    # opt to do external MFA anyways.
    session_mfa_action = deepcopy(session.mfa_action)
    del session.mfa_action

    # Third party service MFA
    if session_mfa_action.success is True:  # Explicit check that success is the boolean True
        current_app.logger.info(f'User {user} logged in using external MFA service {session_mfa_action.issuer}')

        _utc_now = utc_now()

        # External MFA authentication
        sso_session.external_mfa = ExternalMfaData(
            issuer=session_mfa_action.issuer, authn_context=session_mfa_action.authn_context, timestamp=_utc_now
        )
        # Remember the MFA credential used for this particular request
        otc = OnetimeCredential(
            type=OnetimeCredType.external_mfa,
            issuer=sso_session.external_mfa.issuer,
            authn_context=sso_session.external_mfa.authn_context,
            timestamp=_utc_now,
        )
        session.idp.log_credential_used(ref, otc, _utc_now)

        return success_response(payload={'finished': True})

    # External MFA was tried and failed, mfa_action.error is set in the eidas app
    if session_mfa_action.error is not None:
        if session_mfa_action.error is MfaActionError.authn_context_mismatch:
            return error_response(message=IdPMsg.eidas_authn_context_mismatch)
        elif session_mfa_action.error is MfaActionError.authn_too_old:
            return error_response(message=IdPMsg.eidas_reauthn_expired)
        elif session_mfa_action.error is MfaActionError.nin_not_matching:
            return error_response(message=IdPMsg.eidas_nin_not_matching)
        else:
            current_app.logger.warning(f'eidas returned {session_mfa_action.error} that did not match an error message')
            return error_response(message=IdPMsg.general_failure)

    #
    # No external MFA
    #
    if webauthn_response is None:
        payload: Dict[str, Any] = {'finished': False}

        candidates = user.credentials.filter(FidoCredential)
        if candidates.count:
            options = fido_tokens.start_token_verification(user, current_app.conf.fido2_rp_id)
            payload.update(options)

        return success_response(payload=payload)

    #
    # Process webauthn_response
    #
    try:
        result = fido_tokens.verify_webauthn(user, webauthn_response, current_app.conf.fido2_rp_id)
    except fido_tokens.VerificationProblem:
        current_app.logger.exception('Webauthn verification failed')
        current_app.logger.debug(f'webauthn_response: {repr(webauthn_response)}')
        return error_response(message=IdPMsg.mfa_auth_failed)

    current_app.logger.debug(f'verify_webauthn result: {result}')

    if not result.success:
        return error_response(message=IdPMsg.mfa_auth_failed)

    _utc_now = utc_now()

    cred = user.credentials.find(result.credential_key)
    if not cred:
        current_app.logger.error(f'Could not find credential {result.credential_key} on user {user}')
        return error_response(message=IdPMsg.general_failure)

    authn = AuthnData(cred_id=result.credential_key, timestamp=_utc_now)
    sso_session.add_authn_credential(authn)

    current_app.authn.log_authn(user, success=[result.credential_key], failure=[])

    # Remember the MFA credential used for this particular request
    session.idp.log_credential_used(ref, cred, _utc_now)

    return success_response(payload={'finished': True})


@idp_views.route('/tou', methods=['POST'])
@UnmarshalWith(TouRequestSchema)
@MarshalWith(TouResponseSchema)
def tou(ref: RequestRef, versions: Optional[Sequence[str]] = None, user_accepts: Optional[str] = None) -> FluxData:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- Terms of Use ({request.method}) ---')

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_available)

    _info = SAMLQueryParams(request_ref=ref)
    ticket = get_ticket(_info, None)
    if not ticket:
        return error_response(message=IdPMsg.bad_ref)

    if user_accepts:
        if user_accepts != current_app.conf.tou_version:
            return error_response(message=IdPMsg.tou_not_acceptable)

        sso_session = current_app._lookup_sso_session()
        if not sso_session:
            current_app.logger.error(f'TOU called without an SSO session')
            return error_response(message=IdPMsg.general_failure)

        user = current_app.userdb.lookup_user(sso_session.eppn)
        if not user:
            current_app.logger.error(f'User with eppn {sso_session.eppn} (from SSO session) not found')
            return error_response(message=IdPMsg.general_failure)

        current_app.logger.info(f'ToU version {user_accepts} accepted by user {user}')

        tou_user = ToUUser.from_user(user, current_app.tou_db)

        # TODO: change event_id to an UUID? ObjectId is only 'likely unique'
        tou_user.tou.add(ToUEvent(version=user_accepts, created_by='eduid_login', event_id=str(ObjectId())))

        try:
            res = save_and_sync_user(tou_user, private_userdb=current_app.tou_db, app_name_override='eduid_tou')
        except UserOutOfSync:
            current_app.logger.debug(f"Couldn't save ToU {user_accepts} for user {tou_user}, data out of sync")
            return error_response(message=CommonMsg.out_of_sync)

        if not res:
            current_app.logger.error(f'Failed saving/syncing user after accepting ToU')
            return error_response(message=IdPMsg.general_failure)

        return success_response(payload={'finished': True})

    if versions and current_app.conf.tou_version in versions:
        current_app.logger.debug(
            f'Available versions in frontend: {versions}, requesting {current_app.conf.tou_version}'
        )
        return success_response(payload={'finished': False, 'version': current_app.conf.tou_version})

    current_app.logger.debug(
        f'Available versions in frontend: {versions}, current version {current_app.conf.tou_version} is not there'
    )
    return error_response(message=IdPMsg.tou_not_acceptable)
