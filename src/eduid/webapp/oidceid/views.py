from dataclasses import dataclass

from flask import Blueprint, make_response, redirect, request
from werkzeug import Response as WerkzeugResponse

from eduid.common.clients.oidc_client import OidcRpClient, OidcRpError
from eduid.common.config.base import FrontendAction
from eduid.userdb import User
from eduid.userdb.element import ElementKey
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.errors import (
    EduidErrorsContext,
    RejectedCallback,
    goto_errors_response,
    oidc_response_rejected_terminal,
    resolve_oidc_callback,
)
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import AuthnStatusMsg, FluxData, TranslatableMsg, error_response, success_response
from eduid.webapp.common.api.schemas.authn_status import StatusRequestSchema, StatusResponseSchema
from eduid.webapp.common.api.schemas.csrf import EmptyResponse
from eduid.webapp.common.authn.acs_enums import OidcEidAcsAction
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult, get_action
from eduid.webapp.common.proofing.methods import ProofingMethods, ProofingMethodSAML, get_proofing_method
from eduid.webapp.common.proofing.swedenconnect.flow import (
    VERIFY_CREDENTIAL_ACTION,
    apply_action_result,
    build_status_payload,
    check_verify_credential_request,
    remap_staging_nin,
    reset_mfa_action_for_login,
    select_magic_cookie_idp,
)
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import OidcEidAuthnRequest, OIDCState
from eduid.webapp.oidceid.app import CALLBACK_ENDPOINT
from eduid.webapp.oidceid.app import current_oidceid_app as current_app
from eduid.webapp.oidceid.claims import (
    auth_time_datetime,
    build_authn_params,
    claims_to_session_info,
    merge_userinfo,
    scopes_for_method,
)
from eduid.webapp.oidceid.helpers import OIDCEID_MSGS, OidcEidMsg
from eduid.webapp.oidceid.schemas import (
    OidcEidCommonRequestSchema,
    OidcEidCommonResponseSchema,
    OidcEidVerifyCredentialRequestSchema,
)

__author__ = "lundberg"


oidceid_views = Blueprint("oidceid", __name__, url_prefix="")

# The proofing methods this app can request from an OpenID Provider. BankID is added when the OPs support it.
SUPPORTED_METHODS = (ProofingMethods.FREJA, ProofingMethods.EIDAS)


@oidceid_views.route("/", methods=["GET"])
@MarshalWith(EmptyResponse)
@require_user
def index(user: User) -> FluxData:
    return success_response(payload=None, message=None)


# get-status to not get tangled up in /status/healthy and the like
@oidceid_views.route("/get-status", methods=["POST"])
@UnmarshalWith(StatusRequestSchema)
@MarshalWith(StatusResponseSchema)
def get_status(authn_id: OIDCState) -> FluxData:
    authn = session.oidceid.rp.authns.get(authn_id)
    if not authn:
        return error_response(message=AuthnStatusMsg.not_found)

    payload = build_status_payload(authn_id, authn)

    return success_response(payload=payload)


@oidceid_views.route("/verify-credential", methods=["POST"])
@UnmarshalWith(OidcEidVerifyCredentialRequestSchema)
@MarshalWith(OidcEidCommonResponseSchema)
@require_user
def verify_credential(
    user: User, method: str, credential_id: ElementKey, frontend_action: str, frontend_state: str | None = None
) -> FluxData:
    current_app.logger.debug(f"verify-credential called with credential_id: {credential_id}")

    if error := check_verify_credential_request(
        user,
        method,
        credential_id,
        frontend_action,
        OIDCEID_MSGS,
        allow_eidas_credential_verification=current_app.conf.allow_eidas_credential_verification,
        app=current_app,
    ):
        return error

    _frontend_action = VERIFY_CREDENTIAL_ACTION

    result = _authn(
        OidcEidAcsAction.verify_credential,
        method=method,
        frontend_action=_frontend_action.value,
        frontend_state=frontend_state,
        proofing_credential_id=credential_id,
    )

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={"location": result.url})


@oidceid_views.route("/verify-identity", methods=["POST"])
@UnmarshalWith(OidcEidCommonRequestSchema)
@MarshalWith(OidcEidCommonResponseSchema)
@require_user
def verify_identity(user: User, method: str, frontend_action: str, frontend_state: str | None = None) -> FluxData:
    current_app.logger.debug(f"verify-identity called for method {method}")

    result = _authn(
        OidcEidAcsAction.verify_identity,
        method=method,
        frontend_action=frontend_action,
        frontend_state=frontend_state,
    )

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={"location": result.url})


@oidceid_views.route("/mfa-authenticate", methods=["POST"])
@UnmarshalWith(OidcEidCommonRequestSchema)
@MarshalWith(OidcEidCommonResponseSchema)
def mfa_authenticate(method: str, frontend_action: str, frontend_state: str | None = None) -> FluxData:
    current_app.logger.debug("mfa-authenticate called")

    result = _authn(
        OidcEidAcsAction.mfa_authenticate,
        method=method,
        frontend_action=frontend_action,
        frontend_state=frontend_state,
    )

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={"location": result.url})


@oidceid_views.route("/mfa-register", methods=["POST"])
@UnmarshalWith(OidcEidCommonRequestSchema)
@MarshalWith(OidcEidCommonResponseSchema)
def mfa_register(method: str, frontend_action: str, frontend_state: str | None = None) -> FluxData:
    """Start an external MFA authn as the first step of a signup flow."""
    current_app.logger.debug("mfa-register called")

    if frontend_action != FrontendAction.SIGNUP_EXTERNAL_MFA.value:
        current_app.logger.error(f"Invalid frontend_action for mfa-register: {frontend_action}")
        return error_response(message=OidcEidMsg.frontend_action_not_supported)

    result = _authn(
        OidcEidAcsAction.mfa_register,
        method=method,
        frontend_action=frontend_action,
        frontend_state=frontend_state,
    )
    if result.error:
        return error_response(message=result.error)
    return success_response(payload={"location": result.url})


@dataclass
class AuthnResult:
    authn_req: OidcEidAuthnRequest | None = None
    authn_id: OIDCState | None = None
    error: TranslatableMsg | None = None
    url: str | None = None


def _authn(
    action: OidcEidAcsAction,
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
        return AuthnResult(error=OidcEidMsg.frontend_action_not_supported)

    proofing_method = get_proofing_method(method, _frontend_action, current_app.conf)
    current_app.logger.debug(f"Proofing method: {proofing_method}")
    if not isinstance(proofing_method, ProofingMethodSAML) or proofing_method.method not in SUPPORTED_METHODS:
        return AuthnResult(error=OidcEidMsg.method_not_available)

    # The *_idp config values hold the issuer of the OpenID Provider to use
    idp = proofing_method.idp
    if check_magic_cookie(current_app.conf):
        # set a test OP with minimal interaction for the integration tests
        magic_idp = select_magic_cookie_idp(
            proofing_method.method,
            freja_idp=current_app.conf.magic_cookie_idp,
            bankid_idp=current_app.conf.magic_cookie_bankid_idp,
            eidas_idp=current_app.conf.magic_cookie_foreign_id_idp,
        )
        if not magic_idp:
            current_app.logger.error(f"Magic cookie is not supported for method {method}")
            return AuthnResult(error=OidcEidMsg.method_not_available)
        idp = magic_idp
        current_app.logger.debug(f"Changed requested OP due to magic cookie: {idp}")

    client = current_app.oidc_clients.get(idp)
    if client is None:
        current_app.logger.error(f"No OIDC client configured for issuer {idp}")
        return AuthnResult(error=OidcEidMsg.method_not_available)

    try:
        authn_data = client.mint_authn_request(
            redirect_uri=current_app.redirect_uri,
            extra_params=build_authn_params(
                proofing_method.method,
                proofing_method.required_loa,
                current_app.conf,
                force_authn=authn_params.force_authn,
            ),
            scopes=scopes_for_method(proofing_method.method),
        )
    except OidcRpError:
        current_app.logger.exception("Failed to create authorization request")
        return AuthnResult(error=OidcEidMsg.authn_request_failed)

    authn_req = OidcEidAuthnRequest(
        authn_id=OIDCState(authn_data.state),
        frontend_action=_frontend_action,
        frontend_state=frontend_state,
        post_authn_action=action,
        proofing_credential_id=proofing_credential_id,
        method=proofing_method.method,
        finish_url=authn_params.finish_url,
        nonce=authn_data.nonce,
        code_verifier=authn_data.code_verifier,
        redirect_uri=authn_data.redirect_uri,
        oidc_issuer=idp,
    )

    if _frontend_action is FrontendAction.LOGIN_MFA_AUTHN:
        # the IdP matches the login with the authn request in session.mfa_action
        reset_mfa_action_for_login(authn_req.authn_id)

    session.oidceid.rp.authns[authn_req.authn_id] = authn_req
    current_app.logger.debug(f"Stored OidcEidAuthnRequest[{authn_req.authn_id}]: {authn_req}")

    current_app.stats.count(f"{proofing_method.method.value}_authn_request")
    return AuthnResult(authn_id=authn_req.authn_id, url=authn_data.url, authn_req=authn_req)


def _client_for_callback() -> OidcRpClient | None:
    """
    The client of the OpenID Provider the callback's state was sent to, as recorded on the pending authn.

    Never falls back to a default or configured issuer: with several OPs that would let one OP answer a request
    sent to another one (mix-up). None if the state is not an unanswered request in this session.
    """
    states = request.args.getlist("state")
    if len(states) != 1 or not states[0]:
        return None
    authn_req = session.oidceid.rp.authns.get(OIDCState(states[0]))
    if authn_req is None or authn_req.callback_handled or not authn_req.oidc_issuer:
        return None
    client = current_app.oidc_clients.get(authn_req.oidc_issuer)
    if client is None:
        current_app.logger.error(f"No OIDC client for the issuer of request {authn_req.authn_id}")
    return client


@oidceid_views.route("/authn-callback", methods=["GET"])
def authn_callback() -> WerkzeugResponse:
    """
    The callback endpoint of the OIDC flows (the redirect URI registered at the OpenID Providers).
    """
    current_app.logger.debug("authn_callback called")
    current_app.logger.debug(f"request.args keys: {sorted(request.args.keys())!r}")

    client = _client_for_callback()
    if client is None:
        # Unknown, answered or issuer-less state: nothing in the session may be matched. The empty mapping makes
        # sure the response is rejected as unsolicited (or malformed). The response is only shape-checked, by the
        # client of the OP named in its iss if that is a configured one. Without such a client it is unsolicited.
        iss_values = request.args.getlist("iss")
        iss_client = current_app.oidc_clients.get(iss_values[0]) if len(iss_values) == 1 else None
        if iss_client is not None:
            rejected = resolve_oidc_callback(iss_client, request.args, {}, CALLBACK_ENDPOINT)
            if isinstance(rejected, WerkzeugResponse):
                return rejected
        if not current_app.conf.errors_url_template:
            return make_response("Unknown authn response", 400)
        return goto_errors_response(
            errors_url=current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.OIDC_RESPONSE_UNSOLICITED,
            rp=current_app.redirect_uri,
        )

    resolved = resolve_oidc_callback(client, request.args, session.oidceid.rp.authns, CALLBACK_ENDPOINT)
    if isinstance(resolved, WerkzeugResponse):
        return resolved
    authn_req = resolved.authn_req
    assert isinstance(authn_req, OidcEidAuthnRequest)  # noqa: S101 - narrows the type for the checker

    # consume the request before processing, a repeated callback must not run the action again
    authn_req.callback_handled = True
    current_app.stats.count(name="authn_response")

    proofing_method = get_proofing_method(authn_req.method, authn_req.frontend_action, current_app.conf)
    if not isinstance(proofing_method, ProofingMethodSAML) or proofing_method.method not in SUPPORTED_METHODS:
        # We _really_ shouldn't end up here because this same thing would have been done in the
        # starting views above.
        current_app.logger.warning(f"No proofing_method for method {authn_req.method}")
        if not current_app.conf.errors_url_template:
            return make_response("Unknown authn method", 400)
        return goto_errors_response(
            errors_url=current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.OIDC_RESPONSE_FAIL,
            rp=current_app.redirect_uri,
        )
    current_app.stats.count(f"{proofing_method.method.value}_authn_response")

    formatted_finish_url = authn_req.formatted_finish_url(app_name=current_app.conf.app_name)

    if isinstance(resolved, RejectedCallback):
        return oidc_response_rejected_terminal(
            authn_req, status=OidcEidMsg.authorization_error.value, finish_url=formatted_finish_url
        )
    callback = resolved.callback

    if callback.is_error:
        # error and error_description_safe are controlled by the provider: logged escaped, never shown to the user
        current_app.logger.warning(
            f"Provider returned error {callback.error!r} (known: {callback.error_known}), "
            f"description {callback.error_description_safe!r}"
        )
        current_app.stats.count(name="authn_error_response")
        authn_req.error = True
        authn_req.status = OidcEidMsg.authorization_error.value
        return redirect(formatted_finish_url)

    try:
        code = callback.code
        if authn_req.nonce is None or code is None:
            raise OidcRpError("Missing nonce or code")
        authn_result = client.finish(
            code,
            redirect_uri=authn_req.redirect_uri or current_app.redirect_uri,
            nonce=authn_req.nonce,
            code_verifier=authn_req.code_verifier,
        )
        claims = dict(authn_result.claims)
        if claims.get("iss") != authn_req.oidc_issuer:
            raise OidcRpError("ID token issuer does not match the issuer of the request")
        if current_app.conf.fetch_userinfo:
            # claims from the (verified) ID token win over the userinfo response
            claims = merge_userinfo(claims, client.userinfo(authn_result))
        current_app.logger.debug(f"Got claims: {sorted(claims)}")
    except OidcRpError:
        current_app.logger.exception("Failed to get token response from the OpenID Provider")
        current_app.stats.count(name="token_response_failed")
        authn_req.error = True
        authn_req.status = OidcEidMsg.authorization_error.value
        return redirect(formatted_finish_url)

    session_info = claims_to_session_info(claims, method=proofing_method.method)
    if session_info is None:
        # no acr or auth_time: the authentication can not be assessed
        current_app.logger.error("ID token without acr or auth_time claims")
        return apply_action_result(
            ACSResult(message=OidcEidMsg.method_not_available),
            authn_req,
            formatted_finish_url,
            app=current_app,
        )

    # Remap NIN in staging environment
    session_info = remap_staging_nin(
        session_info,
        environment=current_app.conf.environment,
        nin_attribute_map=current_app.conf.nin_attribute_map,
    )

    authn_req.authn_instant = auth_time_datetime(claims.get("auth_time"))

    action = get_action(default_action=None, authndata=authn_req)
    args = ACSArgs(
        session_info=session_info,
        authn_req=authn_req,
        proofing_method=proofing_method,
        backdoor=check_magic_cookie(config=current_app.conf),
    )
    current_app.logger.debug(f"Callback args: authn_req {authn_req}")
    result = action(args=args)
    current_app.logger.debug(f"Callback action result: {result}")

    return apply_action_result(result, args.authn_req, formatted_finish_url, app=current_app)
