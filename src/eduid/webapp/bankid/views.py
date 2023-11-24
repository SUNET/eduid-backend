from dataclasses import dataclass
from typing import Optional
from uuid import uuid4

from flask import Blueprint, make_response, redirect, request
from saml2.request import AuthnRequest
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb import User
from eduid.userdb.element import ElementKey
from eduid.webapp.bankid.app import current_bankid_app as current_app
from eduid.webapp.bankid.helpers import BankIDMsg, check_credential_to_verify, create_authn_info
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.errors import EduidErrorsContext, goto_errors_response
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import CommonMsg, FluxData, TranslatableMsg, error_response, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyResponse
from eduid.webapp.common.authn.acs_enums import BankIDAcsAction
from eduid.webapp.common.authn.acs_registry import ACSArgs, get_action
from eduid.webapp.common.authn.eduid_saml2 import process_assertion
from eduid.webapp.common.authn.utils import get_location
from eduid.webapp.common.proofing.methods import ProofingMethodSAML, get_proofing_method
from eduid.webapp.common.proofing.saml_helpers import create_metadata, is_required_loa, is_valid_reauthn
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import AuthnRequestRef, SP_AuthnRequest

__author__ = "lundberg"

from eduid.webapp.bankid.schemas import (
    BankIDCommonRequestSchema,
    BankIDCommonResponseSchema,
    BankIDStatusRequestSchema,
    BankIDStatusResponseSchema,
    BankIDVerifyCredentialRequestSchema,
)

bankid_views = Blueprint("bankid", __name__, url_prefix="")


@bankid_views.route("/", methods=["GET"])
@MarshalWith(EmptyResponse)
@require_user
def index(user: User) -> FluxData:
    return success_response(payload=None, message=None)


# get_status to not get tangled up in /status/healthy and the like
@bankid_views.route("/get_status", methods=["POST"])
@UnmarshalWith(BankIDStatusRequestSchema)
@MarshalWith(BankIDStatusResponseSchema)
def get_status(authn_id: AuthnRequestRef) -> FluxData:
    authn = session.bankid.sp.authns.get(authn_id)
    if not authn:
        return error_response(message=BankIDMsg.not_found)

    payload = {
        "frontend_action": authn.frontend_action,
        "frontend_state": authn.frontend_state,
        "method": authn.method,
        "error": bool(authn.error),
    }
    if authn.status is not None:
        payload["status"] = authn.status

    return success_response(payload=payload)


@bankid_views.route("/verify-credential", methods=["POST"])
@UnmarshalWith(BankIDVerifyCredentialRequestSchema)
@MarshalWith(BankIDCommonResponseSchema)
@require_user
def verify_credential(
    user: User, method: str, credential_id: ElementKey, frontend_action: str, frontend_state: Optional[str] = None
) -> FluxData:
    current_app.logger.debug(f"verify-credential called with credential_id: {credential_id}")

    # verify that the user has the credential and that it was used for login recently
    ret = check_credential_to_verify(user=user, credential_id=credential_id)
    current_app.logger.debug(f"Credential check result: {ret}")
    if not ret.verified_ok:
        current_app.logger.info(f"Can't proceed with verify-credential at this time: {ret.message}")
        current_app.logger.debug(f"Can't proceed with verify-credential at this time: {ret}")
        return error_response(message=ret.message)

    result = _authn(
        BankIDAcsAction.verify_credential,
        method=method,
        frontend_action=frontend_action,
        frontend_state=frontend_state,
        proofing_credential_id=credential_id,
    )

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={"location": result.url})


@bankid_views.route("/verify-identity", methods=["POST"])
@UnmarshalWith(BankIDCommonRequestSchema)
@MarshalWith(BankIDCommonResponseSchema)
@require_user
def verify_identity(user: User, method: str, frontend_action: str, frontend_state: Optional[str] = None) -> FluxData:
    current_app.logger.debug(f"verify-identity called for method {method}")

    result = _authn(
        BankIDAcsAction.verify_identity,
        method=method,
        frontend_action=frontend_action,
        frontend_state=frontend_state,
    )

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={"location": result.url})


@bankid_views.route("/mfa-authenticate", methods=["POST"])
@UnmarshalWith(BankIDCommonRequestSchema)
@MarshalWith(BankIDCommonResponseSchema)
def mfa_authentication(method: str, frontend_action: str, frontend_state: Optional[str] = None) -> FluxData:
    current_app.logger.debug("mfa-authenticate called")

    result = _authn(
        BankIDAcsAction.mfa_authenticate,
        method=method,
        frontend_action=frontend_action,
        frontend_state=frontend_state,
    )

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={"location": result.url})


@dataclass
class AuthnResult:
    authn_req: Optional[AuthnRequest] = None
    authn_id: Optional[AuthnRequestRef] = None
    error: Optional[TranslatableMsg] = None
    url: Optional[str] = None


def _authn(
    action: BankIDAcsAction,
    method: str,
    frontend_action: str,
    frontend_state: Optional[str] = None,
    proofing_credential_id: Optional[ElementKey] = None,
) -> AuthnResult:
    current_app.logger.debug(f"Requested method: {method}, frontend action: {frontend_action}")
    proofing_method = get_proofing_method(method, frontend_action, current_app.conf)
    current_app.logger.debug(f"Proofing method: {proofing_method}")
    if not proofing_method:
        return AuthnResult(error=BankIDMsg.method_not_available)
    assert isinstance(proofing_method, ProofingMethodSAML)  # please mypy

    idp = proofing_method.idp
    # TODO: We don't have any IdP that works for our automated tests
    # if check_magic_cookie(current_app.conf):
    #    # set a test IdP with minimal interaction for the integration tests
    #    if current_app.conf.magic_cookie_idp:
    #        idp = current_app.conf.magic_cookie_idp
    #        current_app.logger.debug(f"Changed requested IdP due to magic cookie: {idp}")
    #    else:
    #        current_app.logger.error(f"Magic cookie is not supported for method {method}")
    #        return AuthnResult(error=BankIDMsg.method_not_available)

    ref = AuthnRequestRef(str(uuid4()))
    authn_info = create_authn_info(
        authn_ref=ref,
        force_authn=True,
        framework=proofing_method.framework,
        required_loa=proofing_method.required_loa,
        selected_idp=idp,
    )

    session.bankid.sp.authns[ref] = SP_AuthnRequest(
        frontend_action=frontend_action,
        frontend_state=frontend_state,
        post_authn_action=action,
        proofing_credential_id=proofing_credential_id,
        method=proofing_method.method,
    )
    current_app.logger.debug(f"Stored SP_AuthnRequest[{ref}]: {session.bankid.sp.authns[ref]}")

    url = get_location(authn_info)
    if not url:
        current_app.logger.error(f"Couldn't extract Location from {authn_info}")
        return AuthnResult(error=BankIDMsg.method_not_available)

    return AuthnResult(authn_req=authn_info, authn_id=ref, url=url)


@bankid_views.route("/saml2-acs", methods=["POST"])
def assertion_consumer_service() -> WerkzeugResponse:
    """
    Assertion consumer service, receives POSTs from SAML2 IdP's
    """
    assertion = process_assertion(
        form=request.form,
        sp_data=session.bankid.sp,
        authenticate_user=False,  # If the IdP is not our own, we can't load the user
    )
    if isinstance(assertion, WerkzeugResponse):
        return assertion
    current_app.logger.debug(f"Auth response:\n{assertion}\n\n")

    authn_req = session.bankid.sp.authns.get(assertion.authn_req_ref)

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
        assertion.authndata.method,
        assertion.authndata.frontend_action,
        current_app.conf,
    )
    if not proofing_method:
        # We _really_ shouldn't end up here because this same thing would have been done in the
        # starting views above.
        current_app.logger.warning(f"No proofing_method for method {assertion.authndata.method}")
        if not current_app.conf.errors_url_template:
            return make_response("Unknown authn method", 400)
        return goto_errors_response(
            errors_url=current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.SAML_RESPONSE_FAIL,
            rp=current_app.saml2_config.entityid,
        )

    formatted_finish_url = proofing_method.formatted_finish_url(
        app_name=current_app.conf.app_name, authn_id=assertion.authn_req_ref
    )
    assert formatted_finish_url  # please type checking

    assert isinstance(proofing_method, ProofingMethodSAML)  # please mypy
    if not is_required_loa(
        assertion.session_info, proofing_method.required_loa, current_app.conf.authentication_context_map
    ):
        assertion.authndata.error = True
        assertion.authndata.status = BankIDMsg.authn_context_mismatch.value
        return redirect(formatted_finish_url)

    if not is_valid_reauthn(assertion.session_info):
        assertion.authndata.error = True
        assertion.authndata.status = BankIDMsg.must_authenticate.value
        return redirect(formatted_finish_url)

    # assertion checks out try to do the action
    action = get_action(default_action=None, authndata=assertion.authndata)
    backdoor = check_magic_cookie(config=current_app.conf)
    args = ACSArgs(
        session_info=assertion.session_info,
        authn_req=assertion.authndata,
        proofing_method=proofing_method,
        backdoor=backdoor,
    )
    result = action(args=args)
    current_app.logger.debug(f"ACS action result: {result}")

    if not result.success:
        current_app.logger.info(f"SAML ACS action failed: {result.message}")
        # update session so this error can be retrieved from the /status endpoint
        _msg = result.message or CommonMsg.temp_problem
        args.authn_req.status = _msg.value
        args.authn_req.error = True
        return redirect(formatted_finish_url)

    current_app.logger.debug(f"SAML ACS action successful (frontend_action {args.authn_req.frontend_action})")
    if result.message:
        args.authn_req.status = result.message.value
    args.authn_req.error = False

    return redirect(formatted_finish_url)


@bankid_views.route("/saml2-metadata")
def metadata() -> WerkzeugResponse:
    """
    Returns an XML with the SAML 2.0 metadata for this SP as configured in the saml2_settings.py file.
    """
    data = create_metadata(current_app.saml2_config)
    response = make_response(data.to_string(), 200)
    response.headers["Content-Type"] = "text/xml; charset=utf8"
    return response
