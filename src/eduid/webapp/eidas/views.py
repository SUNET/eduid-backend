# -*- coding: utf-8 -*-
from typing import List, Optional, Union
from uuid import uuid4

from flask import Blueprint, abort, make_response, redirect, request
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.config.base import EduidEnvironment
from eduid.userdb import User
from eduid.userdb.credentials.external import TrustFramework
from eduid.userdb.element import ElementKey
from eduid.webapp.common.api.decorators import MarshalWith, require_user
from eduid.webapp.common.api.errors import EduidErrorsContext, goto_errors_response
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import FluxData, redirect_with_msg, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyResponse
from eduid.webapp.common.api.utils import sanitise_redirect_url
from eduid.webapp.common.authn.acs_enums import EidasAcsAction
from eduid.webapp.common.authn.acs_registry import get_action
from eduid.webapp.common.authn.eduid_saml2 import process_assertion
from eduid.webapp.common.authn.utils import get_location
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

eidas_views = Blueprint('eidas', __name__, url_prefix='', template_folder='templates')


@eidas_views.route('/', methods=['GET'])
@MarshalWith(EmptyResponse)
@require_user
def index(user: User) -> FluxData:
    return success_response(payload=None, message=None)


@eidas_views.route('/verify-token/<credential_id>', methods=['GET'])
@require_user
def verify_token(user: User, credential_id: ElementKey) -> Union[FluxData, WerkzeugResponse]:
    current_app.logger.debug(f'verify-token called with credential_id: {credential_id}')
    redirect_url = current_app.conf.token_verify_redirect_url

    # verify that the user has the credential and that it was used for login recently
    ret = check_credential_to_verify(user=user, credential_id=credential_id, redirect_url=redirect_url)
    if ret is not None:
        return ret

    # Store the id of the credential that is supposed to be proofed in the session
    session.eidas.verify_token_action_credential_id = credential_id

    # Request an authentication from the idp
    required_loa = current_app.conf.required_loa
    framework = current_app.conf.trust_framework
    return _authn(EidasAcsAction.token_verify, framework, required_loa, force_authn=True, redirect_url=redirect_url)


@eidas_views.route('/verify-token-foreign-eid/<credential_id>', methods=['GET'])
@require_user
def verify_token_foreign_eid(user: User, credential_id: ElementKey) -> Union[FluxData, WerkzeugResponse]:
    current_app.logger.debug(f'verify-token-foreign-identity called with credential_id: {credential_id}')
    redirect_url = current_app.conf.token_verify_redirect_url

    # verify that the user has the credential and that it was used for login recently
    ret = check_credential_to_verify(user=user, credential_id=credential_id, redirect_url=redirect_url)
    if ret is not None:
        return ret

    # Store the id of the credential that is supposed to be proofed in the session
    session.eidas.verify_token_action_credential_id = credential_id

    # Request an authentication from the idp
    required_loa = current_app.conf.foreign_required_loa
    framework = current_app.conf.foreign_trust_framework
    return _authn(
        EidasAcsAction.token_verify_foreign_eid, framework, required_loa, force_authn=True, redirect_url=redirect_url
    )


@eidas_views.route('/verify-nin', methods=['GET'])
@require_user
def verify_nin(user: User) -> WerkzeugResponse:
    current_app.logger.debug('verify-nin called')
    required_loa = current_app.conf.required_loa
    framework = current_app.conf.trust_framework
    return _authn(
        EidasAcsAction.nin_verify,
        framework,
        required_loa,
        force_authn=True,
        redirect_url=current_app.conf.identity_verify_redirect_url,
    )


@eidas_views.route('/verify-foreign-identity', methods=['GET'])
@require_user
def verify_foreign_identity(user: User) -> WerkzeugResponse:
    current_app.logger.debug('verify-foreign-identity called')
    required_loa = current_app.conf.foreign_required_loa
    framework = current_app.conf.foreign_trust_framework
    eidas_connector = current_app.conf.foreign_identity_idp
    return _authn(
        EidasAcsAction.foreign_identity_verify,
        framework,
        required_loa,
        force_authn=True,
        redirect_url=current_app.conf.identity_verify_redirect_url,
        idp=eidas_connector,
    )


@eidas_views.route('/mfa-authentication', methods=['GET'])
def mfa_authentication() -> WerkzeugResponse:
    current_app.logger.debug('mfa-authentication called')
    redirect_url = sanitise_redirect_url(request.args.get('next', '/'))
    required_loa = current_app.conf.required_loa
    framework = current_app.conf.trust_framework
    return _authn(EidasAcsAction.mfa_authn, framework, required_loa, force_authn=True, redirect_url=redirect_url)


@eidas_views.route('/mfa-authentication-foreign-eid', methods=['GET'])
def mfa_authentication_foreign_eid() -> WerkzeugResponse:
    current_app.logger.debug('mfa-authentication foreign eid called')
    redirect_url = sanitise_redirect_url(request.args.get('next', '/'))
    required_loa = current_app.conf.foreign_required_loa
    framework = current_app.conf.foreign_trust_framework
    return _authn(
        EidasAcsAction.mfa_authn_foreign_eid, framework, required_loa, force_authn=True, redirect_url=redirect_url
    )


def _authn(
    action: EidasAcsAction,
    framework: TrustFramework,
    required_loa: List[str],
    force_authn: bool,
    redirect_url: str,
    idp: Optional[str] = None,
) -> WerkzeugResponse:
    """
    :param action: name of action
    :param required_loa: friendly loa name
    :param force_authn: should a new authentication be forced
    :param redirect_url: redirect url after successful authentication

    :return: redirect response
    """
    login_ref = request.args.get('ref')
    _authn_id = AuthnRequestRef(str(uuid4()))
    session.eidas.sp.authns[_authn_id] = SP_AuthnRequest(post_authn_action=action, redirect_url=redirect_url)
    current_app.logger.debug(f'Stored SP_AuthnRequest[{_authn_id}]: {session.eidas.sp.authns[_authn_id]}')

    if idp is None:
        idp = request.args.get('idp')
    current_app.logger.debug(f'Requested IdP: {idp}')

    if check_magic_cookie(current_app.conf):
        # set a test IdP with minimal interaction for the integration tests
        idp = current_app.conf.magic_cookie_idp
        current_app.logger.debug(f'Changed requested IdP due to magic cookie: {idp}')

    idps: List[str] = current_app.saml2_config.metadata.identity_providers()
    current_app.logger.debug(f'IdPs from metadata: {idps}')

    if idp not in idps:
        if not current_app.conf.errors_url_template:
            abort(make_response('Requested IdP not found in metadata', 404))
        return goto_errors_response(
            errors_url=current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.SAML_REQUEST_MISSING_IDP,
            rp=current_app.saml2_config.entityid,
        )

    authn_request = create_authn_request(
        authn_ref=_authn_id,
        selected_idp=idp,
        framework=framework,
        required_loa=required_loa,
        force_authn=force_authn,
    )
    # Clear session keys used for external mfa
    del session.mfa_action
    # Ideally, we should be able to support multiple ongoing external MFA requests at the same time,
    # but for now at least remember the SAML request id and the login_ref (when the frontend has been
    # updated to supply it to /mfa-authentication) so that the IdP can verify the login_ref matches
    # when processing a successful response in session.mfa_action.
    session.mfa_action.authn_req_ref = _authn_id
    session.mfa_action.login_ref = login_ref
    session.mfa_action.framework = framework
    session.mfa_action.required_loa = required_loa

    current_app.logger.info(f'Redirecting the user to {idp} for {action}')
    return redirect(get_location(authn_request))


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

    if assertion.authn_req_ref != session.mfa_action.authn_req_ref:
        # Perhaps a SAML authn response received out of order - abort without destroying state
        # (User makes two requests, A and B. Response B arrives, user is happy and proceeds with their work.
        #  Then response A arrives late. Just silently abort, no need to mess up the users session.)
        error_url = current_app.conf.unsolicited_response_redirect_url
        current_app.logger.info(
            f'Response {assertion.authn_req_ref} does not match current one in session, '
            f'{session.mfa_action.authn_req_ref}. Redirecting user to {error_url}'
        )
        return redirect(error_url)

    if not is_required_loa(assertion.session_info, session.mfa_action.required_loa):
        session.mfa_action.error = MfaActionError.authn_context_mismatch
        return redirect_with_msg(assertion.authndata.redirect_url, EidasMsg.authn_context_mismatch)

    if not is_valid_reauthn(assertion.session_info):
        session.mfa_action.error = MfaActionError.authn_too_old
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
