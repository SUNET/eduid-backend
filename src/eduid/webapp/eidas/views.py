# -*- coding: utf-8 -*-
from dataclasses import dataclass
from typing import List, Optional, Union
from uuid import uuid4

from flask import Blueprint, abort, make_response, redirect, request
from saml2.request import AuthnRequest
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.config.base import EduidEnvironment
from eduid.userdb import User
from eduid.userdb.credentials.external import TrustFramework
from eduid.userdb.element import ElementKey
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.errors import EduidErrorsContext, goto_errors_response
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import FluxData, error_response, redirect_with_msg, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyResponse
from eduid.webapp.common.api.utils import sanitise_redirect_url
from eduid.webapp.common.authn.acs_enums import EidasAcsAction
from eduid.webapp.common.authn.acs_registry import get_action
from eduid.webapp.common.authn.eduid_saml2 import process_assertion
from eduid.webapp.common.authn.utils import get_location
from eduid.webapp.common.proofing.methods import ProofingMethod, get_proofing_method
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import AuthnRequestRef, MfaActionError, SP_AuthnRequest
from eduid.webapp.eidas.app import current_eidas_app as current_app
from eduid.webapp.eidas.helpers import (
    EidasMsg,
    check_credential_to_verify,
    create_authn_request,
    create_metadata,
    is_required_loa,
    is_valid_reauthn,
    staging_nin_remap,
)

__author__ = 'lundberg'

from eduid.webapp.eidas.schemas import (
    EidasStatusRequestSchema,
    EidasStatusResponseSchema,
    EidasVerifyRequestSchema,
    EidasVerifyResponseSchema,
    EidasVerifyTokenRequestSchema,
    EidasVerifyTokenResponseSchema,
)

eidas_views = Blueprint('eidas', __name__, url_prefix='')


@eidas_views.route('/', methods=['GET'])
@MarshalWith(EmptyResponse)
@require_user
def index(user: User) -> FluxData:
    return success_response(payload=None, message=None)


@eidas_views.route('/status', methods=['POST'])
@UnmarshalWith(EidasStatusRequestSchema)
@MarshalWith(EidasStatusResponseSchema)
@require_user
def status(user: User, authn_id: AuthnRequestRef) -> FluxData:
    authn = session.eidas.sp.authns.get(authn_id)
    if not authn:
        return error_response(message=EidasMsg.not_found)

    return success_response(payload={'frontend_state': authn.frontend_state})


@eidas_views.route('/verify-credential', methods=['POST'])
@UnmarshalWith(EidasVerifyTokenRequestSchema)
@MarshalWith(EidasVerifyTokenResponseSchema)
@require_user
def verify_credential(
    user: User, method: str, credential_id: ElementKey, finish_url: str, frontend_state: Optional[str] = None
) -> FluxData:
    current_app.logger.debug(f'verify-credential called with credential_id: {credential_id}')

    # verify that the user has the credential and that it was used for login recently
    ret = check_credential_to_verify(user=user, credential_id=credential_id)
    if not ret.verified_ok:
        current_app.logger.info(f'Can\'t proceed with verify-credential at this time: {ret.message}')
        current_app.logger.debug(f'Can\'t proceed with verify-credential at this time: {ret}')
        if ret.location:
            return success_response(payload={'location': ret.location}, message=ret.message)
        return error_response(message=ret.message)

    url = None

    if method == 'eidas':
        _authn_req = _authn(
            EidasAcsAction.token_verify_foreign_eid,
            current_app.conf.foreign_trust_framework,
            current_app.conf.foreign_required_loa,
            finish_url=finish_url,
            force_authn=True,
            frontend_state=frontend_state,
            idp=current_app.conf.foreign_identity_idp,
            proofing_credential_id=credential_id,
        )
        url = get_location(_authn_req)
    elif method == 'freja':
        _authn_req = _authn(
            EidasAcsAction.token_verify,
            current_app.conf.trust_framework,
            current_app.conf.required_loa,
            finish_url=finish_url,
            force_authn=True,
            frontend_state=frontend_state,
            idp=current_app.conf.freja_idp,
            proofing_credential_id=credential_id,
        )
        url = get_location(_authn_req)

    if not url:
        return error_response(message=EidasMsg.method_not_available)

    return success_response(payload={'location': url})


@eidas_views.route('/verify-identity', methods=['POST'])
@UnmarshalWith(EidasVerifyRequestSchema)
@MarshalWith(EidasVerifyResponseSchema)
@require_user
def verify_identity(user: User, method: str, finish_url: str, frontend_state: Optional[str] = None) -> FluxData:
    current_app.logger.debug(f'verify-identity called for method {method}')
    url = ''

    proofing_method = get_proofing_method(method)
    if not proofing_method:
        return error_response(message=EidasMsg.method_not_available)

    if method == 'eidas':
        _authn_req = _authn(
            EidasAcsAction.foreign_identity_verify,
            proofing_method=proofing_method,
            finish_url=finish_url,
            frontend_state=frontend_state,
        )
        url = get_location(_authn_req)
    elif method == 'freja':
        _authn_req = _authn(
            EidasAcsAction.nin_verify,
            proofing_method=proofing_method,
            finish_url=finish_url,
            frontend_state=frontend_state,
        )
        url = get_location(_authn_req)

    if not url:
        return error_response(message=EidasMsg.method_not_available)

    return success_response(payload={'location': url})


# TODO: MAKE POST
@eidas_views.route('/mfa-authentication', methods=['GET'])
def mfa_authentication() -> WerkzeugResponse:
    current_app.logger.debug('mfa-authentication called')
    redirect_url = sanitise_redirect_url(request.args.get('next', '/'))
    required_loa = current_app.conf.required_loa
    framework = current_app.conf.trust_framework
    return _authn_redirect(EidasAcsAction.mfa_authn, framework, required_loa, force_authn=True, finish_url=redirect_url)


# TODO: MAKE POST
@eidas_views.route('/mfa-authentication-foreign-eid', methods=['GET'])
def mfa_authentication_foreign_eid() -> WerkzeugResponse:
    current_app.logger.debug('mfa-authentication foreign eid called')
    redirect_url = sanitise_redirect_url(request.args.get('next', '/'))
    required_loa = current_app.conf.foreign_required_loa
    framework = current_app.conf.foreign_trust_framework
    return _authn_redirect(
        EidasAcsAction.mfa_authn_foreign_eid, framework, required_loa, force_authn=True, finish_url=redirect_url
    )


@dataclass
class AuthnResult:
    authn_req: AuthnRequest
    authn_id: AuthnRequestRef


def _authn(
    action: EidasAcsAction,
    proofing_method: ProofingMethod,
    finish_url: str,
    force_authn: bool = True,
    frontend_state: Optional[str] = None,
    proofing_credential_id: Optional[ElementKey] = None,
) -> AuthnResult:
    """
    :param action: name of action
    :param required_loa: friendly loa name
    :param force_authn: should a new authentication be forced
    :param finish_url: redirect url after successful authentication

    :return: redirect response
    """
    current_app.logger.debug(f'Requested proofing: {proofing_method}')

    idp = proofing_method.idp
    if check_magic_cookie(current_app.conf):
        # set a test IdP with minimal interaction for the integration tests
        idp = current_app.conf.magic_cookie_idp
        current_app.logger.debug(f'Changed requested IdP due to magic cookie: {idp}')

    _authn_id = AuthnRequestRef(str(uuid4()))
    authn_request = create_authn_request(
        authn_ref=_authn_id,
        force_authn=force_authn,
        framework=proofing_method.framework,
        required_loa=proofing_method.required_loa,
        selected_idp=idp,
    )

    session.eidas.sp.authns[_authn_id] = SP_AuthnRequest(
        frontend_state=frontend_state,
        post_authn_action=action,
        proofing_credential_id=proofing_credential_id,
        redirect_url=finish_url,
        method=proofing_method.method,
    )
    current_app.logger.debug(f'Stored SP_AuthnRequest[{_authn_id}]: {session.eidas.sp.authns[_authn_id]}')

    return AuthnResult(authn_req=authn_request, authn_id=_authn_id)


@eidas_views.route('/saml2-acs', methods=['POST'])
def assertion_consumer_service() -> WerkzeugResponse:
    """
    Assertion consumer service, receives POSTs from SAML2 IdP's
    """
    assertion = process_assertion(
        form=request.form,
        sp_data=session.eidas.sp,
        error_redirect_url=current_app.conf.unsolicited_response_redirect_url,
        authenticate_user=False,  # If the IdP is not our own, we can't load the user
    )
    if isinstance(assertion, WerkzeugResponse):
        return assertion
    current_app.logger.debug(f'Auth response:\n{assertion}\n\n')

    if session.mfa_action and assertion.authn_req_ref != session.mfa_action.authn_req_ref:
        # Perhaps a SAML authn response received out of order - abort without destroying state
        # (User makes two requests, A and B. Response B arrives, user is happy and proceeds with their work.
        #  Then response A arrives late. Just silently abort, no need to mess up the users' session.)
        error_url = current_app.conf.unsolicited_response_redirect_url
        current_app.logger.info(
            f'Response {assertion.authn_req_ref} does not match current one in session, '
            f'{session.mfa_action.authn_req_ref}. Redirecting user to {error_url}'
        )
        return redirect(error_url)

    if not is_required_loa(assertion.session_info, session.mfa_action.required_loa):
        if session.mfa_action:
            # OLD way
            session.mfa_action.error = MfaActionError.authn_context_mismatch
        assertion.authndata.error = MfaActionError.authn_context_mismatch
        return redirect_with_msg(assertion.authndata.redirect_url, EidasMsg.authn_context_mismatch)

    if not is_valid_reauthn(assertion.session_info):
        if session.mfa_action:
            # OLD way
            session.mfa_action.error = MfaActionError.authn_too_old
        assertion.authndata.error = MfaActionError.authn_too_old
        return redirect_with_msg(assertion.authndata.redirect_url, EidasMsg.reauthn_expired)

    # Remap nin in staging environment
    if current_app.conf.environment == EduidEnvironment.staging:
        assertion.session_info = staging_nin_remap(assertion.session_info)

    action = get_action(default_action=None, authndata=assertion.authndata)
    return action(assertion.session_info, authndata=assertion.authndata)


@eidas_views.route('/saml2-metadata')
def metadata() -> WerkzeugResponse:
    """
    Returns an XML with the SAML 2.0 metadata for this SP as configured in the saml2_settings.py file.
    """
    data = create_metadata(current_app.saml2_config)
    response = make_response(data.to_string(), 200)
    response.headers['Content-Type'] = "text/xml; charset=utf8"
    return response
