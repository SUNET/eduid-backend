from copy import deepcopy
from dataclasses import dataclass

from flask import Blueprint, make_response, redirect, request
from saml2.typing import SAMLHttpArgs
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.config.base import EduidEnvironment, FrontendAction
from eduid.userdb import User
from eduid.userdb.credentials import FidoCredential
from eduid.userdb.element import ElementKey
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.errors import EduidErrorsContext, goto_errors_response
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import (
    AuthnStatusMsg,
    CommonMsg,
    FluxData,
    TranslatableMsg,
    error_response,
    success_response,
)
from eduid.webapp.common.api.schemas.authn_status import StatusRequestSchema, StatusResponseSchema
from eduid.webapp.common.api.schemas.csrf import EmptyResponse
from eduid.webapp.common.authn.acs_enums import SamlEidAcsAction
from eduid.webapp.common.authn.acs_registry import ACSArgs, get_action
from eduid.webapp.common.authn.eduid_saml2 import process_assertion
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.authn.utils import check_reauthn, get_location
from eduid.webapp.common.proofing.methods import ProofingMethodSAML, get_proofing_method
from eduid.webapp.common.proofing.saml_helpers import create_metadata
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import AuthnRequestRef, SP_AuthnRequest
from eduid.webapp.samleid.app import current_samleid_app as current_app
from eduid.webapp.samleid.helpers import SamlEidMsg, create_authn_info
from eduid.webapp.samleid.schemas import (
    SamlEidCommonRequestSchema,
    SamlEidCommonResponseSchema,
    SamlEidVerifyCredentialRequestSchema,
)

__author__ = "lundberg"


samleid_views = Blueprint("samleid", __name__, url_prefix="")


@samleid_views.route("/", methods=["GET"])
@MarshalWith(EmptyResponse)
@require_user
def index(user: User) -> FluxData:
    return success_response(payload=None, message=None)


# get-status to not get tangled up in /status/healthy and the like
@samleid_views.route("/get-status", methods=["POST"])
@UnmarshalWith(StatusRequestSchema)
@MarshalWith(StatusResponseSchema)
def get_status(authn_id: AuthnRequestRef) -> FluxData:
    authn = session.samleid.sp.authns.get(authn_id)
    if not authn:
        return error_response(message=AuthnStatusMsg.not_found)

    payload = {
        "authn_id": authn_id,
        "frontend_action": authn.frontend_action.value,
        "frontend_state": authn.frontend_state,
        "method": authn.method,
        "error": bool(authn.error),
    }
    if authn.status is not None:
        payload["status"] = authn.status

    return success_response(payload=payload)


@samleid_views.route("/verify-credential", methods=["POST"])
@UnmarshalWith(SamlEidVerifyCredentialRequestSchema)
@MarshalWith(SamlEidCommonResponseSchema)
@require_user
def verify_credential(
    user: User, method: str, credential_id: ElementKey, frontend_action: str, frontend_state: str | None = None
) -> FluxData:
    current_app.logger.debug(f"verify-credential called with credential_id: {credential_id}")

    # Check if eidas credential verification is allowed
    if method == "eidas" and current_app.conf.allow_eidas_credential_verification is False:
        current_app.logger.error("Credential verification is not allowed for eidas")
        return error_response(message=SamlEidMsg.credential_verification_not_allowed)

    _frontend_action = FrontendAction.VERIFY_CREDENTIAL

    if frontend_action != _frontend_action.value:
        current_app.logger.error(f"Invalid frontend_action: {frontend_action}")
        return error_response(message=SamlEidMsg.frontend_action_not_supported)

    # verify that the user has the credential and that it was used for login recently
    credential = user.credentials.find(credential_id)
    if credential is None or isinstance(credential, FidoCredential) is False:
        current_app.logger.error(f"Can't find credential with id: {credential_id}")
        return error_response(message=SamlEidMsg.credential_not_found)

    _need_reauthn = check_reauthn(frontend_action=_frontend_action, user=user, credential_requested=credential)
    if _need_reauthn:
        return _need_reauthn

    result = _authn(
        SamlEidAcsAction.verify_credential,
        method=method,
        frontend_action=_frontend_action.value,
        frontend_state=frontend_state,
        proofing_credential_id=credential_id,
    )

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={"location": result.url})


@samleid_views.route("/verify-identity", methods=["POST"])
@UnmarshalWith(SamlEidCommonRequestSchema)
@MarshalWith(SamlEidCommonResponseSchema)
@require_user
def verify_identity(user: User, method: str, frontend_action: str, frontend_state: str | None = None) -> FluxData:
    current_app.logger.debug(f"verify-identity called for method {method}")

    result = _authn(
        SamlEidAcsAction.verify_identity,
        method=method,
        frontend_action=frontend_action,
        frontend_state=frontend_state,
    )

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={"location": result.url})


@samleid_views.route("/mfa-authenticate", methods=["POST"])
@UnmarshalWith(SamlEidCommonRequestSchema)
@MarshalWith(SamlEidCommonResponseSchema)
def mfa_authentication(method: str, frontend_action: str, frontend_state: str | None = None) -> FluxData:
    current_app.logger.debug("mfa-authenticate called")

    result = _authn(
        SamlEidAcsAction.mfa_authenticate,
        method=method,
        frontend_action=frontend_action,
        frontend_state=frontend_state,
    )

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={"location": result.url})


@dataclass
class AuthnResult:
    authn_req: SAMLHttpArgs | None = None
    authn_id: AuthnRequestRef | None = None
    error: TranslatableMsg | None = None
    url: str | None = None


def _authn(
    action: SamlEidAcsAction,
    method: str,
    frontend_action: str,
    frontend_state: str | None = None,
    proofing_credential_id: ElementKey | None = None,
) -> AuthnResult:
    current_app.logger.debug(f"Requested method: {method}, frontend action: {frontend_action}")
    try:
        _frontend_action = FrontendAction(frontend_action)
        authn_params = current_app.conf.frontend_action_authn_parameters[_frontend_action]
    except (ValueError, KeyError):
        current_app.logger.exception(f"Frontend action {frontend_action} not supported")
        return AuthnResult(error=SamlEidMsg.frontend_action_not_supported)

    proofing_method = get_proofing_method(method, _frontend_action, current_app.conf)
    current_app.logger.debug(f"Proofing method: {proofing_method}")
    if not proofing_method:
        return AuthnResult(error=SamlEidMsg.method_not_available)
    assert isinstance(proofing_method, ProofingMethodSAML)  # please mypy

    idp = proofing_method.idp
    if check_magic_cookie(current_app.conf):
        # set a test IdP with minimal interaction for the integration tests
        if current_app.conf.magic_cookie_idp:
            if proofing_method.method == "freja" and current_app.conf.magic_cookie_idp:
                idp = current_app.conf.magic_cookie_idp
            elif proofing_method.method == "eidas" and current_app.conf.magic_cookie_foreign_id_idp:
                idp = current_app.conf.magic_cookie_foreign_id_idp
            else:
                current_app.logger.error(f"Magic cookie is not supported for method {method}")
                return AuthnResult(error=SamlEidMsg.method_not_available)
            current_app.logger.debug(f"Changed requested IdP due to magic cookie: {idp}")
        else:
            current_app.logger.warning("Missing configuration magic_cookie_idp")

    authn_req = SP_AuthnRequest(
        frontend_action=_frontend_action,
        frontend_state=frontend_state,
        post_authn_action=action,
        proofing_credential_id=proofing_credential_id,
        method=proofing_method.method,
        finish_url=authn_params.finish_url,
    )

    authn_info = create_authn_info(
        authn_ref=authn_req.authn_id,
        force_authn=authn_params.force_authn,
        framework=proofing_method.framework,
        required_loa=proofing_method.required_loa,
        selected_idp=idp,
    )

    if _frontend_action is FrontendAction.LOGIN_MFA_AUTHN:
        # TODO:
        # 1. Release code that stores all this in both the SP_AuthnRequest, and the old place: session.mfa_action
        # 2. When all sessions in Redis has data in both places, update the ACS function to read from the new place
        #   IdP should look up any FrontendAction.LOGIN_MFA_AUTHN authn requests and match frontend state with the
        #   current login ref. We should make something similar for reset password.
        # 3. Remove session.mfa_action
        #
        # Make sure only expected keys are used for external mfa, clear the rest
        saved_mfa_action = deepcopy(session.mfa_action)
        del session.mfa_action
        session.mfa_action.login_ref = saved_mfa_action.login_ref
        session.mfa_action.eppn = saved_mfa_action.eppn

        # Ideally, we should be able to support multiple ongoing external MFA requests at the same time,
        # but for now at least remember the SAML request id and the login_ref (when the frontend has been
        # updated to supply it to /mfa-authentication) so that the IdP can verify the login_ref matches
        # when processing a successful response in session.mfa_action.
        session.mfa_action.authn_req_ref = authn_req.authn_id

    session.samleid.sp.authns[authn_req.authn_id] = authn_req
    current_app.logger.debug(
        f"Stored SP_AuthnRequest[{authn_req.authn_id}]: {session.samleid.sp.authns[authn_req.authn_id]}"
    )

    url = get_location(authn_info)
    if not url:
        current_app.logger.error(f"Couldn't extract Location from {authn_info}")
        return AuthnResult(error=SamlEidMsg.method_not_available)

    return AuthnResult(authn_req=authn_info, authn_id=authn_req.authn_id, url=url)


def _attribute_remap(session_info: SessionInfo) -> SessionInfo:
    """
    Remap NIN attributes in staging environment for testing purposes.

    :param session_info: SAML session info containing user attributes
    :returns: Modified session info with remapped NIN if applicable
    """
    personal_identity_number = session_info.get("ava", {}).get("personalIdentityNumber")
    if personal_identity_number:
        asserted_test_nin = personal_identity_number[0]
        user_nin = current_app.conf.nin_attribute_map.get(asserted_test_nin, None)
        if user_nin:
            session_info["ava"]["personalIdentityNumber"] = [user_nin]
    return session_info


@samleid_views.route("/saml2-acs", methods=["POST"])
def assertion_consumer_service() -> WerkzeugResponse:
    """
    Assertion consumer service, receives POSTs from SAML2 IdP's
    """
    assertion = process_assertion(
        form=request.form,
        sp_data=session.samleid.sp,
        authenticate_user=False,  # If the IdP is not our own, we can't load the user
    )
    if isinstance(assertion, WerkzeugResponse):
        return assertion
    current_app.logger.debug(f"Auth response:\n{assertion}\n\n")

    authn_req = session.samleid.sp.authns.get(assertion.authn_req_ref)

    if not authn_req:
        # Perhaps a SAML authn response received out of order - abort without destroying state
        # (User makes two requests, A and B. Response B arrives, user is happy and proceeds with their work.
        #  Then response A arrives late. Just silently abort, no need to mess up the users' session.)
        current_app.logger.info(
            f"Response {assertion.authn_req_ref} does not match one in session, redirecting user to eduID Errors page"
        )
        if not current_app.conf.errors_url_template:
            return make_response("Unknown authn response", 400)
        return goto_errors_response(
            errors_url=current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.SAML_RESPONSE_UNSOLICITED,
            rp=current_app.saml2_config.entityid,
        )

    proofing_method = get_proofing_method(
        assertion.authn_data.method, assertion.authn_data.frontend_action, current_app.conf
    )
    if not proofing_method:
        # We _really_ shouldn't end up here because this same thing would have been done in the
        # starting views above.
        current_app.logger.warning(f"No proofing_method for method {assertion.authn_data.method}")
        if not current_app.conf.errors_url_template:
            return make_response("Unknown authn method", 400)
        return goto_errors_response(
            errors_url=current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.SAML_RESPONSE_FAIL,
            rp=current_app.saml2_config.entityid,
        )

    # Remap NIN in staging environment
    if current_app.conf.environment in [EduidEnvironment.staging, EduidEnvironment.dev]:
        assertion.session_info = _attribute_remap(assertion.session_info)

    action = get_action(default_action=None, authndata=assertion.authn_data)
    backdoor = check_magic_cookie(config=current_app.conf)
    args = ACSArgs(
        session_info=assertion.session_info,
        authn_req=assertion.authn_data,
        proofing_method=proofing_method,
        backdoor=backdoor,
    )
    result = action(args=args)
    current_app.logger.debug(f"ACS action result: {result}")

    formatted_finish_url = proofing_method.formatted_finish_url(
        app_name=current_app.conf.app_name, authn_id=assertion.authn_req_ref
    )
    assert formatted_finish_url  # please type checking

    if not result.success:
        current_app.logger.info(f"SAML ACS action failed: {result.message}")
        # update session so this error can be retrieved from the /status endpoint
        _msg = result.message or CommonMsg.temp_problem
        args.authn_req.status = _msg.value
        args.authn_req.error = True
        args.authn_req.consumed = True
        return redirect(formatted_finish_url)

    current_app.logger.debug(f"SAML ACS action successful (frontend_action {args.authn_req.frontend_action})")
    if result.message:
        args.authn_req.status = result.message.value
    args.authn_req.error = False
    args.authn_req.consumed = True
    return redirect(formatted_finish_url)


@samleid_views.route("/saml2-metadata")
def metadata() -> WerkzeugResponse:
    """
    Returns an XML with the SAML 2.0 metadata for this SP as configured in the saml2_settings.py file.
    """
    data = create_metadata(current_app.saml2_config)
    response = make_response(data.to_string(), 200)
    response.headers["Content-Type"] = "text/xml; charset=utf8"
    return response
