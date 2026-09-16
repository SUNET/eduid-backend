import json
from urllib.parse import parse_qs, urlparse

from flask import Blueprint, make_response, redirect, request, url_for
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.clients.oidc_client import OidcRpError
from eduid.common.config.base import FrontendAction
from eduid.userdb.proofing import ProofingUser
from eduid.userdb.user import User
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.errors import EduidErrorsContext, goto_errors_response
from eduid.webapp.common.api.messages import (
    AuthnStatusMsg,
    FluxData,
    error_response,
    success_response,
)
from eduid.webapp.common.api.schemas.authn_status import StatusRequestSchema, StatusResponseSchema
from eduid.webapp.common.api.schemas.csrf import EmptyRequest
from eduid.webapp.common.api.utils import save_and_sync_user
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

    try:
        authorization_url = current_app.oidc_client.authorization_url(
            redirect_uri=url_for("orcid.authn_callback", _external=True),
            extra_params={"claims": json.dumps({"userinfo": {"id": None}})},
        )
    except OidcRpError:
        current_app.logger.exception("Failed to create authorization request")
        return error_response(message=OrcidMsg.authz_error)

    auth_url_query = urlparse(authorization_url).query
    try:
        state = parse_qs(auth_url_query)["state"][0]
    except KeyError:
        current_app.logger.error(f'Failed to parse "state" from authn request: {auth_url_query}')
        return error_response(message=OrcidMsg.authz_error)

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

    current_app.logger.debug(f"Stored RP_AuthnRequest[{oidc_state}]: {authn_req}")
    current_app.stats.count(name="authn_request")
    return success_response(payload={"location": authorization_url})


@orcid_views.route("/authorization-response", methods=["GET"])
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

    try:
        token_response = current_app.oidc_client.fetch_token()
        current_app.logger.debug(f"Got token response: {token_response}")
        userinfo_response = current_app.oidc_client.userinfo()
        current_app.logger.debug(f"Got userinfo response: {userinfo_response}")
    except OidcRpError:
        current_app.logger.exception("Failed to get token/userinfo response from ORCID")
        current_app.stats.count(name="token_response_failed")
        authn_req.error = True
        authn_req.status = OrcidMsg.authz_error.value
        return redirect(formatted_finish_url)

    current_app.logger.info("ORCID authorized for user")

    # authlib/joserfc leaves 'aud' as decoded from the JWT - ORCID issues it as a bare string, but
    # OidcIdToken.aud is typed list[str], so normalize it here before building session_info.
    id_token_claims = dict(token_response["userinfo"])
    if isinstance(id_token_claims.get("aud"), str):
        id_token_claims["aud"] = [id_token_claims["aud"]]

    # Build session_info for callback action
    session_info = SessionInfo(
        {
            "id_token": id_token_claims,
            "userinfo": dict(userinfo_response),
            "access_token": token_response["access_token"],
            "token_type": token_response["token_type"],
            "expires_in": token_response.get("expires_in"),
            "refresh_token": token_response.get("refresh_token"),
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
