# -*- coding: utf-8 -*-
from dataclasses import dataclass
from typing import Optional
from uuid import uuid4

from flask import Blueprint, make_response, redirect, request
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.config.base import EduidEnvironment
from eduid.userdb import User
from eduid.userdb.element import ElementKey
from eduid.webapp.authn.views import FALLBACK_FRONTEND_ACTION
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.errors import EduidErrorsContext, goto_errors_response
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import (
    FluxData,
    TranslatableMsg,
    error_response,
    redirect_with_msg,
    success_response,
)
from eduid.webapp.common.api.schemas.csrf import EmptyResponse
from eduid.webapp.common.authn.acs_enums import EidasAcsAction
from eduid.webapp.common.authn.acs_registry import ACSArgs, get_action
from eduid.webapp.common.authn.eduid_saml2 import process_assertion
from eduid.webapp.common.authn.utils import get_location
from eduid.webapp.common.proofing.methods import get_proofing_method
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
from saml2.request import AuthnRequest

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

    return success_response(payload={'frontend_action': authn.frontend_action, 'frontend_state': authn.frontend_state})


@eidas_views.route('/verify-credential', methods=['POST'])
@UnmarshalWith(EidasVerifyTokenRequestSchema)
@MarshalWith(EidasVerifyTokenResponseSchema)
@require_user
def verify_credential(
    user: User, method: str, credential_id: ElementKey, frontend_action: str, frontend_state: Optional[str] = None
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

    result = _authn(
        EidasAcsAction.verify_credential,
        method=method,
        frontend_action=frontend_action,
        frontend_state=frontend_state,
        proofing_credential_id=credential_id,
    )

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={'location': result.url})


@eidas_views.route('/verify-identity', methods=['POST'])
@UnmarshalWith(EidasVerifyRequestSchema)
@MarshalWith(EidasVerifyResponseSchema)
@require_user
def verify_identity(user: User, method: str, frontend_action: str, frontend_state: Optional[str] = None) -> FluxData:
    current_app.logger.debug(f'verify-identity called for method {method}')

    result = _authn(
        EidasAcsAction.verify_identity,
        method=method,
        frontend_action=frontend_action,
        frontend_state=frontend_state,
    )

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={'location': result.url})


@eidas_views.route('/mfa-authenticate', methods=['POST'])
@UnmarshalWith(EidasVerifyRequestSchema)
@MarshalWith(EidasVerifyResponseSchema)
def mfa_authentication(method: str, frontend_action: str, frontend_state: Optional[str] = None) -> FluxData:
    current_app.logger.debug('mfa-authenticate called')

    result = _authn(
        EidasAcsAction.mfa_authenticate,
        method=method,
        frontend_action=frontend_action,
        frontend_state=frontend_state,
    )

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={'location': result.url})


@dataclass
class AuthnResult:
    authn_req: Optional[AuthnRequest] = None
    authn_id: Optional[AuthnRequestRef] = None
    error: Optional[TranslatableMsg] = None
    url: Optional[str] = None


def _authn(
    action: EidasAcsAction,
    method: str,
    frontend_action: str,
    frontend_state: Optional[str] = None,
    proofing_credential_id: Optional[ElementKey] = None,
    redirect_url: Optional[str] = None,  # DEPRECATED - try to use frontend_action instead
) -> AuthnResult:
    current_app.logger.debug(f'Requested method: {method}, frontend action: {frontend_action}')

    fallback_url = None
    if frontend_action == FALLBACK_FRONTEND_ACTION:
        fallback_url = redirect_url

    proofing_method = get_proofing_method(method, frontend_action, current_app.conf, fallback_redirect_url=fallback_url)
    current_app.logger.debug(f'Proofing method: {proofing_method}')
    if not proofing_method or not proofing_method.finish_url:
        return AuthnResult(error=EidasMsg.method_not_available)

    idp = proofing_method.idp
    if check_magic_cookie(current_app.conf):
        # set a test IdP with minimal interaction for the integration tests
        if current_app.conf.magic_cookie_idp:
            idp = current_app.conf.magic_cookie_idp
            current_app.logger.debug(f'Changed requested IdP due to magic cookie: {idp}')
        else:
            current_app.logger.warning(f'Missing configuration magic_cookie_idp')

    ref = AuthnRequestRef(str(uuid4()))
    authn_request = create_authn_request(
        authn_ref=ref,
        force_authn=True,
        framework=proofing_method.framework,
        required_loa=proofing_method.required_loa,
        selected_idp=idp,
    )

    session.eidas.sp.authns[ref] = SP_AuthnRequest(
        frontend_action=frontend_action,
        frontend_state=frontend_state,
        post_authn_action=action,
        proofing_credential_id=proofing_credential_id,
        method=proofing_method.method,
        redirect_url=redirect_url,  # DEPRECATED - try to use frontend_action instead
    )
    current_app.logger.debug(f'Stored SP_AuthnRequest[{ref}]: {session.eidas.sp.authns[ref]}')

    url = get_location(authn_request)  # type: ignore
    if not url:
        current_app.logger.error(f"Couldn't extract Location from {authn_request}")
        return AuthnResult(error=EidasMsg.method_not_available)

    return AuthnResult(authn_req=authn_request, authn_id=ref, url=url)


@eidas_views.route('/saml2-acs', methods=['POST'])
def assertion_consumer_service() -> WerkzeugResponse:
    """
    Assertion consumer service, receives POSTs from SAML2 IdP's
    """
    assertion = process_assertion(
        form=request.form,
        sp_data=session.eidas.sp,
        authenticate_user=False,  # If the IdP is not our own, we can't load the user
    )
    if isinstance(assertion, WerkzeugResponse):
        return assertion
    current_app.logger.debug(f'Auth response:\n{assertion}\n\n')

    authn_req = session.eidas.sp.authns.get(assertion.authn_req_ref)

    if not authn_req:
        # Perhaps a SAML authn response received out of order - abort without destroying state
        # (User makes two requests, A and B. Response B arrives, user is happy and proceeds with their work.
        #  Then response A arrives late. Just silently abort, no need to mess up the users' session.)
        current_app.logger.info(
            f'Response {assertion.authn_req_ref} does not match one in session, redirecting user to eduID Errors page'
        )
        if not current_app.conf.errors_url_template:
            return make_response('Unknown authn response', 400)
        return goto_errors_response(
            errors_url=current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.SAML_RESPONSE_UNSOLICITED,
            rp=current_app.saml2_config.entityid,
        )

    fallback_url = None
    if assertion.authndata.frontend_action == FALLBACK_FRONTEND_ACTION:
        fallback_url = assertion.authndata.redirect_url

    proofing_method = get_proofing_method(
        assertion.authndata.method,
        assertion.authndata.frontend_action,
        current_app.conf,
        fallback_redirect_url=fallback_url,
    )
    if not proofing_method or not proofing_method.finish_url:
        # We _really_ shouldn't end up here because this same thing would have been done in the
        # starting views above.
        current_app.logger.warning(f'No proofing_method for method {assertion.authndata.method}')
        if not current_app.conf.errors_url_template:
            return make_response('Unknown authn method', 400)
        return goto_errors_response(
            errors_url=current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.SAML_RESPONSE_FAIL,
            rp=current_app.saml2_config.entityid,
        )

    if not is_required_loa(assertion.session_info, proofing_method.required_loa):
        session.mfa_action.error = MfaActionError.authn_context_mismatch  # TODO: Old way, remove after a release cycle
        assertion.authndata.error = EidasMsg.authn_context_mismatch.value
        return redirect_with_msg(proofing_method.finish_url, EidasMsg.authn_context_mismatch)

    if not is_valid_reauthn(assertion.session_info):
        session.mfa_action.error = MfaActionError.authn_too_old  # TODO: Old way, remove after a release cycle
        assertion.authndata.error = EidasMsg.reauthn_expired.value
        return redirect_with_msg(proofing_method.finish_url, EidasMsg.reauthn_expired)

    # Remap nin in staging environment
    if current_app.conf.environment == EduidEnvironment.staging:
        assertion.session_info = staging_nin_remap(assertion.session_info)

    action = get_action(default_action=None, authndata=assertion.authndata)
    backdoor = check_magic_cookie(config=current_app.conf)
    args = ACSArgs(
        session_info=assertion.session_info,
        authn_req=assertion.authndata,
        proofing_method=proofing_method,
        backdoor=backdoor,
    )
    result = action(args)
    current_app.logger.debug(f'ACS action result: {result}')

    if result.error:
        current_app.logger.info(f'SAML ACS action failed: {result.error}')
        # update session so this error can be retrieved from the /status endpoint
        args.authn_req.error = result.error.value
        # Including the error in the redirect URL is deprecated and should be removed once frontend stops using it
        return redirect_with_msg(proofing_method.finish_url, result.error, error=True)

    if result.success:
        current_app.logger.debug(f'SAML ACS action successful (frontend_action {args.authn_req.frontend_action})')
        if args.authn_req.frontend_action == FALLBACK_FRONTEND_ACTION:
            return redirect_with_msg(proofing_method.finish_url, EidasMsg.action_completed, error=False)
        return redirect(proofing_method.finish_url)

    return redirect_with_msg(proofing_method.finish_url, EidasMsg.method_not_available)


@eidas_views.route('/saml2-metadata')
def metadata() -> WerkzeugResponse:
    """
    Returns an XML with the SAML 2.0 metadata for this SP as configured in the saml2_settings.py file.
    """
    data = create_metadata(current_app.saml2_config)
    response = make_response(data.to_string(), 200)
    response.headers['Content-Type'] = "text/xml; charset=utf8"
    return response
