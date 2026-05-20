from urllib.parse import urlencode

from flask import Blueprint, make_response, redirect, request, url_for
from oic.oic.message import AuthorizationResponse, Claims, ClaimsRequest
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.config.base import FrontendAction
from eduid.userdb.proofing import ProofingUser
from eduid.userdb.user import User
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.errors import EduidErrorsContext, goto_errors_response
from eduid.webapp.common.api.messages import (
    AuthnStatusMsg,
    CommonMsg,
    FluxData,
    error_response,
    success_response,
)
from eduid.webapp.common.api.oidc import OidcServiceUnavailableError
from eduid.webapp.common.api.schemas.authn_status import StatusRequestSchema, StatusResponseSchema
from eduid.webapp.common.api.schemas.csrf import EmptyRequest
from eduid.webapp.common.api.utils import get_unique_hash, save_and_sync_user
from eduid.webapp.common.authn.acs_registry import ACSArgs, get_action
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import OIDCState, RP_AuthnRequest
from eduid.webapp.orcid.app import current_orcid_app as current_app
from eduid.webapp.orcid.callback_enums import OrcidAction
from eduid.webapp.orcid.helpers import OrcidMsg
from eduid.webapp.orcid.schemas import OrcidConnectRequestSchema, OrcidConnectResponseSchema, OrcidResponseSchema

orcid_views = Blueprint("orcid", __name__, url_prefix="", template_folder="templates")


@orcid_views.route("/get-status", methods=["POST"])
@UnmarshalWith(StatusRequestSchema)
@MarshalWith(StatusResponseSchema)
@require_user
def get_status(user: User, authn_id: OIDCState) -> FluxData:
    authn = session.orcid.rp.authns.get(authn_id)
    if not authn:
        return error_response(message=AuthnStatusMsg.not_found)

    payload = {
        "authn_id": str(authn_id),
        "frontend_action": authn.frontend_action.value,
        "frontend_state": authn.frontend_state,
        "method": authn.method,
        "error": bool(authn.error),
    }
    if authn.status is not None:
        payload["status"] = authn.status

    return success_response(payload=payload)


@orcid_views.route("/connect-orcid", methods=["POST"])
@UnmarshalWith(OrcidConnectRequestSchema)
@MarshalWith(OrcidConnectResponseSchema)
@require_user
def connect_orcid(user: User, frontend_action: str, frontend_state: str | None = None) -> FluxData:
    if user.orcid is not None:
        return error_response(message=OrcidMsg.already_connected)

    try:
        _frontend_action = FrontendAction(frontend_action)
        authn_params = current_app.conf.frontend_action_authn_parameters[_frontend_action]
    except (ValueError, KeyError):
        current_app.logger.error(f"Frontend action {frontend_action} not supported")
        return error_response(message=OrcidMsg.frontend_action_not_supported)

    state = get_unique_hash()
    nonce = get_unique_hash()

    try:
        claims_request = ClaimsRequest(userinfo=Claims(id=None))  # type: ignore[no-untyped-call]
        oidc_args = {
            "client_id": current_app.oidc_client.client_id,
            "response_type": "code",
            "scope": "openid",
            "claims": claims_request.to_json(),  # type: ignore[no-untyped-call]
            "redirect_uri": url_for("orcid.authn_callback", _external=True),
            "state": state,
            "nonce": nonce,
        }
        authorization_url = f"{current_app.oidc_client.authorization_endpoint}?{urlencode(oidc_args)}"
    except OidcServiceUnavailableError as e:
        current_app.logger.warning(f"ORCID service unavailable during authorization: {e}")
        return error_response(message=CommonMsg.temp_problem)

    oidc_state = OIDCState(state)
    authn_req = RP_AuthnRequest(
        authn_id=oidc_state,
        frontend_action=_frontend_action,
        frontend_state=frontend_state,
        post_authn_action=OrcidAction.connect_orcid,
        method="orcid",
        finish_url=authn_params.finish_url,
    )
    session.orcid.rp.authns[oidc_state] = authn_req
    session.orcid.nonces[oidc_state] = nonce

    current_app.logger.debug(f"Stored RP_AuthnRequest[{oidc_state}]: {authn_req}")
    current_app.stats.count(name="authn_request")
    return success_response(payload={"location": authorization_url})


@orcid_views.route("/authn-callback", methods=["GET"])
@require_user
def authn_callback(user: User) -> WerkzeugResponse:
    current_app.logger.debug(f"authn_callback called with args: {request.args}")

    oidc_state: OIDCState | None = None
    authn_req: RP_AuthnRequest | None = None
    if "state" in request.args:
        oidc_state = OIDCState(request.args["state"])
    if oidc_state is not None:
        authn_req = session.orcid.rp.authns.get(oidc_state)

    if not oidc_state or not authn_req:
        current_app.logger.info(
            f"Response {oidc_state} does not match one in session, redirecting user to eduID Errors page"
        )
        if not current_app.conf.errors_url_template:
            return make_response("Unknown authn response", 400)
        return goto_errors_response(
            errors_url=current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.OIDC_RESPONSE_UNSOLICITED,
            rp=url_for("orcid.authn_callback", _external=True),
        )

    current_app.stats.count(name="authn_response")
    formatted_finish_url = authn_req.formatted_finish_url(app_name=current_app.conf.app_name)

    # Parse authorization response
    query_string = request.query_string.decode("utf-8")
    try:
        authn_resp = current_app.oidc_client.parse_response(
            AuthorizationResponse, info=query_string, sformat="urlencoded"
        )
    except OidcServiceUnavailableError as e:
        current_app.logger.warning(f"ORCID service unavailable during authorization response: {e}")
        authn_req.error = True
        authn_req.status = CommonMsg.temp_problem.value
        return redirect(formatted_finish_url)

    if authn_resp.get("error"):  # type: ignore[no-untyped-call]
        current_app.logger.error(
            f"AuthorizationError: {authn_resp['error']} - {authn_resp.get('error_message')}"  # type: ignore[no-untyped-call]
            f" ({authn_resp.get('error_description')})"  # type: ignore[no-untyped-call]
        )
        authn_req.error = True
        authn_req.status = OrcidMsg.authz_error.value
        return redirect(formatted_finish_url)

    # Token request
    args = {
        "code": authn_resp["code"],
        "redirect_uri": url_for("orcid.authn_callback", _external=True),
    }
    try:
        token_resp = current_app.oidc_client.do_access_token_request(  # type: ignore[no-untyped-call]
            scope="openid", state=authn_resp["state"], request_args=args, authn_method="client_secret_basic"
        )
        id_token = token_resp["id_token"]

        # Validate nonce
        expected_nonce = session.orcid.nonces.get(oidc_state)
        if not expected_nonce or id_token["nonce"] != expected_nonce:
            current_app.logger.error("The 'nonce' parameter does not match for user")
            authn_req.error = True
            authn_req.status = OrcidMsg.unknown_nonce.value
            return redirect(formatted_finish_url)

        # Nonce validated, remove it
        del session.orcid.nonces[oidc_state]

        current_app.logger.info("ORCID authorized for user")

        # Userinfo request
        userinfo_result = current_app.oidc_client.do_user_info_request(  # type: ignore[no-untyped-call]
            method=current_app.conf.userinfo_endpoint_method, state=authn_resp["state"]
        )
    except OidcServiceUnavailableError as e:
        current_app.logger.warning(f"ORCID service unavailable during token/userinfo request: {e}")
        authn_req.error = True
        authn_req.status = CommonMsg.temp_problem.value
        return redirect(formatted_finish_url)

    # Build session_info for callback action
    session_info = SessionInfo(
        {
            "id_token": dict(id_token),
            "userinfo": dict(userinfo_result),
            "access_token": token_resp["access_token"],
            "token_type": token_resp["token_type"],
            "expires_in": token_resp["expires_in"],
            "refresh_token": token_resp["refresh_token"],
        }
    )

    action = get_action(default_action=None, authndata=authn_req)
    acs_args = ACSArgs(
        session_info=session_info,
        authn_req=authn_req,
    )
    result = action(args=acs_args)
    current_app.logger.debug(f"Callback action result: {result}")

    if not result.success:
        current_app.logger.info(f"OIDC callback action failed: {result.message}")
        current_app.stats.count(name="authn_action_failed")
        authn_req.error = True
        if result.message:
            authn_req.status = result.message.value
        authn_req.consumed = True
        return redirect(formatted_finish_url)

    current_app.logger.debug(f"OIDC callback action successful (frontend_action {authn_req.frontend_action})")
    if result.message:
        authn_req.status = result.message.value
    authn_req.consumed = True
    return redirect(formatted_finish_url)


@orcid_views.route("/", methods=["GET"])
@MarshalWith(OrcidResponseSchema)
@require_user
def get_orcid(user: User) -> FluxData:
    return success_response(payload=user.to_dict())


@orcid_views.route("/remove", methods=["POST"])
@UnmarshalWith(EmptyRequest)
@MarshalWith(OrcidResponseSchema)
@require_user
def remove_orcid(user: User) -> FluxData:
    current_app.logger.info("Removing ORCID data for user")
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    proofing_user.orcid = None
    save_and_sync_user(proofing_user)
    current_app.logger.info("ORCID data removed for user")
    return success_response(payload=proofing_user.to_dict())
