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
import base64
import json
from copy import deepcopy
from dataclasses import asdict, dataclass
from io import BytesIO
from typing import Any, Dict, List, Optional, Sequence, Union
from uuid import uuid4

import qrcode
import user_agents
from bson import ObjectId
from flask import Blueprint, jsonify, redirect, request, url_for
from werkzeug.exceptions import BadRequest
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.config.base import EduidEnvironment
from eduid.common.misc.encoders import EduidJSONEncoder
from eduid.common.misc.timeutil import utc_now
from eduid.common.utils import urlappend
from eduid.userdb import LockedIdentityNin, ToUEvent
from eduid.userdb.actions.tou import ToUUser
from eduid.userdb.credentials import FidoCredential, Password
from eduid.userdb.exceptions import UserOutOfSync
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.exceptions import EduidForbidden, EduidTooManyRequests
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.models import FluxSuccessResponse
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.authn import fido_tokens
from eduid.webapp.common.session import session
from eduid.webapp.common.session.logindata import (
    ExternalMfaData,
    LoginContext,
    LoginContextOtherDevice,
    LoginContextSAML,
)
from eduid.webapp.common.session.namespaces import (
    IdP_OtherDevicePendingRequest,
    IdP_SAMLPendingRequest,
    MfaActionError,
    OnetimeCredType,
    OnetimeCredential,
    RequestRef,
)
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance import get_requested_authn_context
from eduid.webapp.idp.helpers import IdPAction, IdPMsg
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.login import SSO, do_verify, get_ticket, login_next_step, show_login_page
from eduid.webapp.idp.logout import SLO

__author__ = 'ft'

from eduid.webapp.idp.other_device import OtherDevice, make_short_code
from eduid.webapp.idp.other_device_data import OtherDeviceId, OtherDeviceState
from eduid.webapp.idp.util import get_ip_proximity

from saml2 import BINDING_HTTP_POST

from eduid.webapp.idp.mischttp import parse_query_string, set_sso_cookie
from eduid.webapp.idp.schemas import (
    AuthnOptionsRequestSchema,
    AuthnOptionsResponseSchema,
    MfaAuthRequestSchema,
    MfaAuthResponseSchema,
    NextRequestSchema,
    NextResponseSchema,
    PwAuthRequestSchema,
    PwAuthResponseSchema,
    TouRequestSchema,
    TouResponseSchema,
    UseOther1RequestSchema,
    UseOther1ResponseSchema,
    UseOther2RequestSchema,
    UseOther2ResponseSchema,
)
from eduid.webapp.idp.service import SAMLQueryParams
from eduid.webapp.idp.sso_session import SSOSession, record_authentication

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

        # TODO: Remove all this code, we don't use the template IdP anymore.
        if not current_app.conf.enable_legacy_template_mode:
            raise BadRequest('Template IdP not enabled')

        # please mypy with this legacy code
        assert isinstance(ticket, LoginContextSAML)

        return show_login_page(ticket)

    if request.method == 'POST':
        return do_verify()

    raise BadRequest()


@idp_views.route('/authn_options', methods=['POST'])
@UnmarshalWith(AuthnOptionsRequestSchema)
@MarshalWith(AuthnOptionsResponseSchema)
def authn_options(ref: RequestRef) -> FluxData:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- Authn options {ref} ---')

    _info = SAMLQueryParams(request_ref=ref)
    ticket = get_ticket(_info, None)
    if not ticket:
        return error_response(message=IdPMsg.bad_ref)
    current_app.logger.debug(f'Extra debug: LoginContext: {asdict(ticket)}')
    current_app.logger.debug(f'Extra debug: Pending request: {ticket.pending_request}')

    payload: Dict[str, Any] = {
        'usernamepassword': True,
        'password': False,
        'other_device': current_app.conf.allow_other_device_logins,
        'webauthn': False,
        'freja_eidplus': False,
    }

    if ticket.is_other_device == 2:
        current_app.logger.debug(f'This is a request to log in to another device, not allowing other_device')
        payload['other_device'] = False

    sso_session = current_app._lookup_sso_session()
    if not sso_session:
        current_app.logger.debug(f'No SSO session, responding {payload}')
        return success_response(payload=payload)

    user = current_app.userdb.lookup_user(sso_session.eppn)
    if user:
        if user.credentials.filter(Password):
            current_app.logger.debug(f'User in SSO session has a Password credential')
            _password = True

        if user.credentials.filter(FidoCredential):
            current_app.logger.debug(f'User in SSO session has a FIDO/Webauthn credential')
            _webauthn = True

        if user.locked_identity.filter(LockedIdentityNin):
            current_app.logger.debug(f'User in SSO session has a locked NIN -> Freja is possible')
            _freja = True

        if user.mail_addresses.primary:
            # Provide e-mail from (potentially expired) SSO session to frontend, so it can populate
            # the username field for the user
            _mail = user.mail_addresses.primary.email
            current_app.logger.debug(f'User in SSO session has a primary e-mail -> username {_mail}')
            payload['username'] = _mail

    current_app.logger.debug(f'Responding with authn options: {payload}')
    return success_response(payload=payload)


@idp_views.route('/next', methods=['POST'])
@UnmarshalWith(NextRequestSchema)
@MarshalWith(NextResponseSchema)
def next(ref: RequestRef) -> FluxData:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- Next ({ref}) ---')

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_available)

    _info = SAMLQueryParams(request_ref=ref)
    ticket = get_ticket(_info, None)
    if not ticket:
        _pending = session.idp.pending_requests
        current_app.logger.debug(f'Login ref {ref} not found in pending_requests: {_pending.keys()}')
        return error_response(message=IdPMsg.bad_ref)

    sso_session = current_app._lookup_sso_session()

    _next = login_next_step(ticket, sso_session)
    current_app.logger.debug(f'Login Next: {_next}')

    if _next.message == IdPMsg.other_device:
        _payload = {
            'action': IdPAction.OTHER_DEVICE.value,
            'target': url_for('idp.use_other_1', _external=True),
        }

        return success_response(message=IdPMsg.must_authenticate, payload=_payload,)

    if _next.message == IdPMsg.must_authenticate:
        _payload = {
            'action': IdPAction.PWAUTH.value,
            'target': url_for('idp.pw_auth', _external=True),
        }

        return success_response(message=IdPMsg.must_authenticate, payload=_payload,)

    if _next.message == IdPMsg.mfa_required:
        return success_response(
            message=IdPMsg.mfa_required,
            payload={'action': IdPAction.MFA.value, 'target': url_for('idp.mfa_auth', _external=True),},
        )

    if _next.message == IdPMsg.tou_required:
        return success_response(
            message=IdPMsg.tou_required,
            payload={'action': IdPAction.TOU.value, 'target': url_for('idp.tou', _external=True)},
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

        if isinstance(ticket, LoginContextSAML):
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
        elif isinstance(ticket, LoginContextOtherDevice):
            if not current_app.conf.allow_other_device_logins:
                return error_response(message=IdPMsg.not_available)

            state = ticket.other_device_req
            if ticket.is_other_device == 1:
                # We shouldn't be able to get here, but this clearly shows where this code runs
                current_app.logger.warning(f'Ticket is LoginContextOtherDevice, but this is use other device #1')
            elif ticket.is_other_device == 2:
                if state.device2.ref != ticket.request_ref:
                    current_app.logger.warning(f'Tried to use OtherDevice state that is not ours: {state}')
                    return error_response(message=IdPMsg.general_failure)  # TODO: make a real error code for this

                if state.expires_at < utc_now():
                    current_app.stats.count('login_using_other_device_finish_too_late')
                    current_app.logger.error(f'Request to login using another device was expired: {state}')
                    # TODO: better response code
                    return error_response(message=IdPMsg.general_failure)

                if state.state == OtherDeviceState.IN_PROGRESS:
                    current_app.logger.debug(f'Recording login using another device {state.state_id} as finished')
                    current_app.logger.debug(f'Extra debug: SSO eppn {sso_session.eppn}')
                    _state = current_app.other_device_db.logged_in(
                        state, sso_session.eppn, ticket.pending_request.credentials_used
                    )
                    if not _state:
                        current_app.logger.warning(f'Failed to finish state: {state.state_id}')
                        return error_response(message=IdPMsg.general_failure)
                    current_app.logger.info(f'Finished login with other device state {state.state_id}')
                    current_app.stats.count('login_using_other_device_finish')

                return success_response(
                    message=IdPMsg.finished,
                    payload={'action': IdPAction.FINISHED.value, 'target': url_for('idp.use_other_2', _external=True)},
                )
        current_app.logger.error(f'Don\'t know how to finish login request {ticket}')
        return error_response(message=IdPMsg.general_failure)

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

    # Create/update SSO session
    current_app.logger.debug(f'User {pwauth.user} authenticated OK ({type(ticket)} request id {ticket.request_id})')
    _sso_session = current_app._lookup_sso_session()
    _authn_credentials: List[AuthnData] = []
    if pwauth.authndata:
        _authn_credentials = [pwauth.authndata]
    _sso_session = record_authentication(
        ticket, pwauth.user.eppn, _sso_session, _authn_credentials, current_app.conf.sso_session_lifetime
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
    saved_mfa_action = deepcopy(session.mfa_action)
    del session.mfa_action

    # Third party service MFA
    if saved_mfa_action.success is True:  # Explicit check that success is the boolean True
        current_app.logger.info(f'User {user} logged in using external MFA service {saved_mfa_action.issuer}')

        _utc_now = utc_now()

        # External MFA authentication
        sso_session.external_mfa = ExternalMfaData(
            issuer=saved_mfa_action.issuer, authn_context=saved_mfa_action.authn_context, timestamp=_utc_now
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
    if saved_mfa_action.error is not None:
        if saved_mfa_action.error is MfaActionError.authn_context_mismatch:
            return error_response(message=IdPMsg.eidas_authn_context_mismatch)
        elif saved_mfa_action.error is MfaActionError.authn_too_old:
            return error_response(message=IdPMsg.eidas_reauthn_expired)
        elif saved_mfa_action.error is MfaActionError.nin_not_matching:
            return error_response(message=IdPMsg.eidas_nin_not_matching)
        else:
            current_app.logger.warning(f'eidas returned {saved_mfa_action.error} that did not match an error message')
            return error_response(message=IdPMsg.general_failure)

    #
    # No external MFA
    #
    if webauthn_response is None:
        payload: Dict[str, Any] = {'finished': False}

        candidates = user.credentials.filter(FidoCredential)
        if candidates:
            options = fido_tokens.start_token_verification(user, current_app.conf.fido2_rp_id, session.mfa_action)
            payload.update(options)

        return success_response(payload=payload)

    #
    # Process webauthn_response
    #
    if not saved_mfa_action.webauthn_state:
        current_app.logger.error(f'No active webauthn challenge found in the session, can\'t do verification')
        return error_response(message=IdPMsg.general_failure)

    try:
        result = fido_tokens.verify_webauthn(user, webauthn_response, current_app.conf.fido2_rp_id, saved_mfa_action)
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
    current_app.logger.debug(f'AuthnData to save: {authn}')

    current_app.logger.debug(f'Saving SSO session {sso_session}')
    current_app.sso_sessions.save(sso_session)

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

        if current_app.conf.environment == EduidEnvironment.dev:
            # Filter out old events for the same version, to not get too much log spam with hundreds
            # of ToUEvent on users in development logs
            keys_with_version = [x.key for x in tou_user.tou.to_list() if x.version == user_accepts]
            for remove_key in keys_with_version[:-2]:
                # remove all but the last two of this version
                tou_user.tou.remove(remove_key)

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


@idp_views.route('/use_other_1', methods=['POST'])
@UnmarshalWith(UseOther1RequestSchema)
@MarshalWith(UseOther1ResponseSchema)
def use_other_1(
    ref: RequestRef, username: Optional[str] = None, action: Optional[str] = None, response_code: Optional[str] = None
) -> Union[FluxData, WerkzeugResponse]:
    """
    The user requests to start a "Login using another device" flow.

    This function sets up a new state for that in the database, and returns a QR code with a reference to that state.

    The QR code is the transferred (by the user) to another device (device #2), where the actual use of credentials
    will take place. The state will then be updated with the authentication information, and the user can
    retrieve them again on this device (device #1).
    """
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- Use Other Device #1 ({ref}, username {username}, action {action}) ---')

    if not current_app.conf.allow_other_device_logins or not current_app.conf.other_device_url:
        return error_response(message=IdPMsg.not_available)

    _lookup_result = _get_other_device_state_using_ref(ref, device=1)
    if _lookup_result.response:
        return _lookup_result.response

    ticket = _lookup_result.ticket
    state = _lookup_result.state
    # ensure mypy
    assert ticket

    sso_session = current_app._lookup_sso_session()

    if not state and (not action or action == 'FETCH'):
        if sso_session:
            username = sso_session.eppn
        user = None
        if username:
            user = current_app.authn.userdb.lookup_user(username)

        current_app.logger.debug(f'Adding new use other device state')
        state = current_app.other_device_db.add_new_state(ticket, user, ttl=current_app.conf.other_device_logins_ttl)
        ticket.set_other_device_state(state.state_id)
        if state.eppn:
            current_app.stats.count('login_using_other_device_start_with_eppn')
        else:
            current_app.stats.count('login_using_other_device_start_anonymous')
        current_app.logger.info(f'Added new use other device state: {state.state_id}')

    if not state:
        current_app.logger.info(f'Login using other device: State not found, or not added')
        return error_response(message=IdPMsg.state_not_found)

    now = utc_now()
    # passing expires_at to the frontend would require clock sync to be usable,
    # while passing number of seconds left is pretty unambiguous
    expires_in = (state.expires_at - now).total_seconds()

    payload: Dict[str, Any] = {}

    if state.expires_at > now:
        if action == 'FETCH':
            pass
        elif action == 'ABORT':
            if state.state in [OtherDeviceState.NEW, OtherDeviceState.IN_PROGRESS]:
                current_app.logger.info('Aborting login using another device')
                _state = current_app.other_device_db.abort(state)
                if not _state:
                    current_app.logger.warning(f'Login using other device: Failed aborting state {state}')
                    return error_response(message=IdPMsg.general_failure)
                state = _state
                current_app.stats.count('login_using_other_device_abort')
                ticket.set_other_device_state(None)
                expires_in = 0
            else:
                current_app.logger.info(f'Not aborting use other device in state {state.state}')
        elif action == 'SUBMIT_CODE':
            if state.state in [OtherDeviceState.LOGGED_IN]:
                if response_code == state.device2.response_code:
                    if not state.eppn:
                        current_app.logger.warning(f'Login using other device: No eppn in state {state.state_id}')
                        current_app.logger.debug(f'Extra debug: Full other device state:\n{state.to_json()}')
                        return error_response(message=IdPMsg.general_failure)

                    current_app.logger.info(
                        f'Use other device: Transferring {len(state.device2.credentials_used)} credentials used to '
                        f'login ref {ticket.request_ref}'
                    )
                    state.state = OtherDeviceState.FINISHED
                    ticket.pending_request.credentials_used = state.device2.credentials_used
                    ticket.set_other_device_state(None)

                    # Create/update SSO session
                    _authn_credentials: List[AuthnData] = []
                    for key, ts in state.device2.credentials_used.items():
                        authn = AuthnData(cred_id=key, timestamp=ts)
                        _authn_credentials += [authn]
                    sso_session = record_authentication(
                        ticket, state.eppn, sso_session, _authn_credentials, current_app.conf.sso_session_lifetime
                    )

                    current_app.logger.debug(f'Saving SSO session {sso_session}')
                    current_app.sso_sessions.save(sso_session)

                    current_app.stats.count('login_using_other_device_finished')
                else:
                    current_app.logger.info(f'Use other device: Incorrect response_code')
                    current_app.stats.count('login_using_other_device_incorrect_code')
                    state.bad_attempts += 1
            else:
                current_app.logger.info(f'Not validating response code for use other device in state {state.state}')
                state.bad_attempts += 1

            if state.state != OtherDeviceState.DENIED:
                if state.bad_attempts >= current_app.conf.other_device_max_code_attempts:
                    current_app.logger.info(f'Use other device: too many response code attempts')
                    current_app.stats.count('login_using_other_device_denied')
                    state.state = OtherDeviceState.DENIED

            if not current_app.other_device_db.save(state):
                current_app.logger.warning(f'Login using other device: Failed saving state {state}')
                return error_response(message=IdPMsg.general_failure)
        elif action is not None:
            current_app.logger.error(f'Login using other device: Unknown action: {action}')
            return error_response(message=IdPMsg.general_failure)
    else:
        age = int((now - state.expires_at).total_seconds())
        current_app.logger.info(f'Use other device state is expired ({age} seconds)')

    if state.state in [OtherDeviceState.NEW, OtherDeviceState.IN_PROGRESS]:
        # Only add QR code when it will actually be displayed
        buf = BytesIO()
        qr_url = urlappend(current_app.conf.other_device_url, str(state.state_id))
        qrcode.make(qr_url).save(buf)
        qr_b64 = base64.b64encode(buf.getvalue())

        current_app.logger.debug(f'Use-other URL: {qr_url} (QR: {len(qr_b64)} bytes)')
        payload.update(
            {
                'qr_url': qr_url,  # shown in non-production environments
                'qr_img': f'data:image/png;base64, {qr_b64.decode("ascii")}',
            }
        )

    payload.update(
        {
            'expires_max': current_app.conf.other_device_logins_ttl.total_seconds(),
            'state_id': state.state_id,  # TODO: Make a secretbox with the state_id in it here
            'state': state.state.value,
            'short_code': state.short_code,
            'expires_in': expires_in,
        }
    )

    # NOTE: It is CRITICAL to never return the response code to Device #1
    if sso_session:
        # In case we created the SSO session above, we need to return it's ID to the user in a cookie
        _flux_response = FluxSuccessResponse(request, payload=payload)
        resp = jsonify(UseOther1ResponseSchema().dump(_flux_response.to_dict()))

        return set_sso_cookie(sso_session.session_id, resp)

    return success_response(payload=payload)


@idp_views.route('/use_other_2', methods=['POST'])
@UnmarshalWith(UseOther2RequestSchema)
@MarshalWith(UseOther2ResponseSchema)
def use_other_2(ref: Optional[RequestRef], state_id: Optional[OtherDeviceId]) -> FluxData:
    """ "Login using another device" flow.

    This is the first step on device #2. When the user has scanned the QR code, the frontend will fetch state
    using this endpoint.
    """
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- Use Other Device #2 (ref {ref}, state_id {state_id}) ---')

    if not current_app.conf.allow_other_device_logins:
        return error_response(message=IdPMsg.not_available)

    state = None

    if ref:
        _lookup_result = _get_other_device_state_using_ref(ref, device=2)
        if _lookup_result.response:
            return _lookup_result.response

        state = _lookup_result.state
    elif state_id:
        # Load state using state_id from QR URL
        current_app.logger.debug(f'Other device: Loading state using state_id: {state_id} (from QR code)')
        state = current_app.other_device_db.get_state_by_id(state_id)
        if not state:
            current_app.logger.debug(f'Other device: State with state_id {state_id} (from QR code) not found')
        else:
            current_app.logger.info(f'Loaded other device state: {state.state_id}')
            current_app.logger.debug(f'Extra debug: Full other device state:\n{state.to_json()}')

    if not state:
        current_app.logger.debug(f'Other device: No state found, bailing out')
        return error_response(message=IdPMsg.state_not_found)

    if state.state == OtherDeviceState.NEW:
        # Grab this state and associate it with the current browser session. This is important so that
        # it's not possible for an attacker to initiate other device, send QR code to victim, have them
        # use it and log in and then use the QR code to retrieve the response code.
        request_ref = RequestRef(str(uuid4()))
        _state = current_app.other_device_db.grab(state, request_ref)
        if not _state:
            current_app.logger.warning(f'Failed to grab state: {state.state_id}')
            return error_response(message=IdPMsg.general_failure)
        current_app.logger.info(f'Grabbed login with other device state {state.state_id}')
        state = _state
        pending = IdP_OtherDevicePendingRequest(state_id=state.state_id)
        session.idp.pending_requests[request_ref] = pending
        current_app.logger.debug(f'Created new pending request with ref {request_ref}: {pending}')

    if ref and state.device2.ref != ref:
        current_app.logger.warning(
            f'Tried to use OtherDevice state that is not ours: {state.device2.ref} != {ref} (ours)'
        )
        current_app.logger.debug(f'Extra debug: Full other device state:\n{state.to_json()}')
        return error_response(message=IdPMsg.general_failure)  # TODO: make a real error code for this

    # passing expires_at to the frontend would require clock sync to be usable,
    # while passing number of seconds left is pretty unambiguous
    now = utc_now()
    expires_in = (state.expires_at - now).total_seconds()

    # The frontend will present the user with the option to proceed with this login on this device #2.
    # If the user proceeds, the frontend can now call the /next endpoint with the ref returned in this response.
    device_info = {
        'addr': state.device1.ip_address,
        'description': str(user_agents.parse(state.device1.user_agent)),
        'proximity': get_ip_proximity(state.device1.ip_address, request.remote_addr).value,
    }

    payload: Dict[str, Any] = {
        'device1_info': device_info,
        'expires_in': expires_in,
        'expires_max': current_app.conf.other_device_logins_ttl.total_seconds(),
        'login_ref': state.device2.ref,
        'short_code': state.short_code,
        'state': state.state.value,
    }

    if state.state == OtherDeviceState.LOGGED_IN:
        # Be very explicit about when response_code is returned.
        payload['response_code'] = state.device2.response_code
    else:
        # This really shouldn't happen, but better ensure it like this.
        if 'response_code' in payload:
            current_app.logger.error(f'Response code found in use other device state {state.state} payload - removing')
            del payload['response_code']

    return success_response(payload=payload)


@dataclass
class OtherDeviceRefResult:
    response: Optional[FluxData] = None
    ticket: Optional[LoginContext] = None
    state: Optional[OtherDevice] = None


def _get_other_device_state_using_ref(ref: RequestRef, device: int) -> OtherDeviceRefResult:
    """ Look for existing OtherDevice state using a login ref """
    _info = SAMLQueryParams(request_ref=ref)
    ticket = get_ticket(_info, None)
    if not ticket:
        return OtherDeviceRefResult(response=error_response(message=IdPMsg.bad_ref))
    current_app.logger.debug(f'Extra debug: LoginContext: {asdict(ticket)}')
    current_app.logger.debug(f'Extra debug: Pending request: {ticket.pending_request}')

    # Check both callers opinion of what device this is, and the states. Belts and bracers.
    if device == 1 or ticket.is_other_device == 1:
        if isinstance(ticket.pending_request, IdP_OtherDevicePendingRequest):
            current_app.logger.warning(f'Not allowing recursive login using another device')
            return OtherDeviceRefResult(response=error_response(message=IdPMsg.not_available))
    elif device == 2 or ticket.is_other_device == 2:
        if not isinstance(ticket.pending_request, IdP_OtherDevicePendingRequest):
            current_app.logger.warning(f'The pending request is not an IdP_OtherDevicePendingRequest')
            return OtherDeviceRefResult(response=error_response(message=IdPMsg.not_available))

    state = None
    if ticket.other_device_state_id:
        current_app.logger.debug(f'Looking for other device state using id from ticket: {ticket.other_device_state_id}')
        # Retrieve OtherDevice state. It might be expired though, in case we just create a new one.
        state = current_app.other_device_db.get_state_by_id(ticket.other_device_state_id)
        if not state:
            current_app.logger.info('OtherDevice state not found, clearing it')
            ticket.set_other_device_state(None)

    if state:
        current_app.logger.info(f'Loaded other device state: {state.state_id}')
        current_app.logger.debug(f'Extra debug: Full other device state:\n{state.to_json()}')

    return OtherDeviceRefResult(ticket=ticket, state=state)
