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
from typing import List

from flask import Blueprint, redirect, request, url_for
from werkzeug.exceptions import BadRequest
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.exceptions import EduidForbidden, EduidTooManyRequests
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import ReqSHA1, RequestRef
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance import get_requested_authn_context
from eduid.webapp.idp.helpers import IdPAction, IdPMsg
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.login import SSO, do_verify, get_ticket, login_next_step, show_login_page
from eduid.webapp.idp.logout import SLO

__author__ = 'ft'

from eduid.webapp.idp.mischttp import parse_query_string
from eduid.webapp.idp.schemas import NextRequestSchema, NextResponseSchema, PwAuthRequestSchema, PwAuthResponseSchema
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
        return error_response(message=IdPMsg.not_implemented)

    _info = SAMLQueryParams(request_ref=ref)
    ticket = get_ticket(_info, None)
    if not ticket:
        return error_response(message=IdPMsg.bad_ref)

    sso_session = current_app._lookup_sso_session()

    _next = login_next_step(ticket, sso_session)
    current_app.logger.debug(f'Login Next: {_next}')

    if _next.message == IdPMsg.must_authenticate:
        return success_response(
            message=IdPMsg.must_authenticate, payload={'action': IdPAction.PWAUTH, 'target': url_for('idp.pwauth')}
        )

    if _next.message == IdPMsg.user_terminated:
        return error_response(message=IdPMsg.user_terminated)
    if _next.message == IdPMsg.swamid_mfa_required:
        return error_response(message=IdPMsg.swamid_mfa_required)
    if _next.message == IdPMsg.mfa_required:
        return error_response(message=IdPMsg.mfa_required)

    return error_response(message=IdPMsg.not_implemented)


@idp_views.route('/pwauth', methods=['POST'])
@UnmarshalWith(PwAuthRequestSchema)
@MarshalWith(PwAuthResponseSchema)
def pwauth(ref: RequestRef, username: str, password: str) -> FluxData:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- Password authentication ({request.method}) ---')

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_implemented)

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
        user_id=pwauth.user.user_id,
        authn_request_id=ticket.saml_req.request_id,
        authn_credentials=_authn_credentials,
        idp_user=pwauth.user,
        eppn=pwauth.user.eppn,
    )

    # This session contains information about the fact that the user was authenticated. It is
    # used to avoid requiring subsequent authentication for the same user during a limited
    # period of time, by storing the session-id in a browser cookie.
    current_app.sso_sessions.save(_sso_session)
    current_app.logger.debug(f'Saved SSO session {repr(_sso_session.session_id)}')

    # INFO-Log the request id and the sso_session
    authn_ref = get_requested_authn_context(ticket)
    current_app.logger.debug(f'Authenticating with {repr(authn_ref)}')

    current_app.logger.info(
        f'{ticket.request_ref}: login sso_session={_sso_session.public_id}, authn={authn_ref}, user={pwauth.user}'
    )

    # Remember the password credential used for this particular request
    session.idp.log_credential_used(ticket.request_ref, pwauth.credential, pwauth.timestamp)

    return success_response(payload={'finished': True})
