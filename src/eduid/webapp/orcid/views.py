from urllib.parse import urlencode

from flask import Blueprint, redirect, request, url_for
from oic.oic.message import AuthorizationResponse, Claims, ClaimsRequest
from pydantic import ValidationError
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb.logs import OrcidProofing
from eduid.userdb.orcid import OidcAuthorization, OidcIdToken, Orcid
from eduid.userdb.proofing import OrcidProofingState, ProofingUser
from eduid.userdb.user import User
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.messages import (
    CommonMsg,
    FluxData,
    TranslatableMsg,
    redirect_with_msg,
    success_response,
)
from eduid.webapp.common.api.oidc import OidcServiceUnavailableError
from eduid.webapp.common.api.schemas.csrf import EmptyRequest
from eduid.webapp.common.api.utils import get_unique_hash, save_and_sync_user
from eduid.webapp.orcid.app import current_orcid_app as current_app
from eduid.webapp.orcid.helpers import OrcidMsg, OrcidUserinfo
from eduid.webapp.orcid.schemas import OrcidResponseSchema

__author__ = "lundberg"

orcid_views = Blueprint("orcid", __name__, url_prefix="", template_folder="templates")


@orcid_views.route("/authorize", methods=["GET"])
@require_user
def authorize(user: User) -> WerkzeugResponse:
    if user.orcid is None:
        try:
            proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn)
            if not proofing_state:
                current_app.logger.debug(f"No proofing state found for user {user!s}. Initializing new proofing state.")
                proofing_state = OrcidProofingState(
                    id=None, modified_ts=None, eppn=user.eppn, state=get_unique_hash(), nonce=get_unique_hash()
                )
                current_app.proofing_statedb.save(proofing_state, is_in_database=False)

            claims_request = ClaimsRequest(userinfo=Claims(id=None))
            oidc_args = {
                "client_id": current_app.oidc_client.client_id,
                "response_type": "code",
                "scope": "openid",
                "claims": claims_request.to_json(),
                "redirect_uri": url_for("orcid.authorization_response", _external=True),
                "state": proofing_state.state,
                "nonce": proofing_state.nonce,
            }
            authorization_url = f"{current_app.oidc_client.authorization_endpoint}?{urlencode(oidc_args)}"
            current_app.logger.debug(f"Authorization url: {authorization_url!s}")
            current_app.stats.count(name="authn_request")
            return redirect(authorization_url)
        except OidcServiceUnavailableError as e:
            current_app.logger.warning(f"ORCID service unavailable during authorization: {e}")
            redirect_url = current_app.conf.orcid_verify_redirect_url
            return redirect_with_msg(redirect_url, CommonMsg.temp_problem, error=True)
    # Orcid already connected to user
    redirect_url = current_app.conf.orcid_verify_redirect_url
    return redirect_with_msg(redirect_url, OrcidMsg.already_connected)


@orcid_views.route("/authorization-response", methods=["GET"])
@require_user
def authorization_response(user: User) -> WerkzeugResponse:
    # Redirect url for user feedback
    redirect_url = current_app.conf.orcid_verify_redirect_url

    current_app.stats.count(name="authn_response")

    # parse authentication response
    query_string = request.query_string.decode("utf-8")
    current_app.logger.debug(f"query_string: {query_string!s}")

    try:
        authn_resp = current_app.oidc_client.parse_response(
            AuthorizationResponse, info=query_string, sformat="urlencoded"
        )
        current_app.logger.debug(f"Authorization response received: {authn_resp!s}")
    except OidcServiceUnavailableError as e:
        current_app.logger.warning(f"ORCID service unavailable during authorization response: {e}")
        return redirect_with_msg(redirect_url, CommonMsg.temp_problem, error=True)

    if authn_resp.get("error"):
        current_app.logger.error(
            "AuthorizationError from {}: {} - {} ({})".format(
                request.host, authn_resp["error"], authn_resp.get("error_message"), authn_resp.get("error_description")
            )
        )
        return redirect_with_msg(redirect_url, OrcidMsg.authz_error)

    user_oidc_state = authn_resp["state"]
    proofing_state = current_app.proofing_statedb.get_state_by_oidc_state(user_oidc_state)
    if not proofing_state:
        current_app.logger.error(f"The 'state' parameter ({user_oidc_state!s}) does not match a user state.")
        return redirect_with_msg(redirect_url, OrcidMsg.no_state)

    # do token request
    args = {
        "code": authn_resp["code"],
        "redirect_uri": url_for("orcid.authorization_response", _external=True),
    }
    current_app.logger.debug(f"Trying to do token request: {args!s}")
    try:
        token_resp = current_app.oidc_client.do_access_token_request(
            scope="openid", state=authn_resp["state"], request_args=args, authn_method="client_secret_basic"
        )
        current_app.logger.debug(f"token response received: {token_resp!s}")
        id_token = token_resp["id_token"]
        if id_token["nonce"] != proofing_state.nonce:
            current_app.logger.error("The 'nonce' parameter does not match for user")
            return redirect_with_msg(redirect_url, OrcidMsg.unknown_nonce)

        current_app.logger.info("ORCID authorized for user")

        # do userinfo request
        current_app.logger.debug("Trying to do userinfo request:")
        userinfo_result = current_app.oidc_client.do_user_info_request(
            method=current_app.conf.userinfo_endpoint_method, state=authn_resp["state"]
        )
        current_app.logger.debug(f"userinfo received: {userinfo_result}")
    except OidcServiceUnavailableError as e:
        current_app.logger.warning(f"ORCID service unavailable during token/userinfo request: {e}")
        return redirect_with_msg(redirect_url, CommonMsg.temp_problem, error=True)

    try:
        userinfo = OrcidUserinfo(**userinfo_result)
    except ValidationError as e:
        current_app.logger.error(f"Failed to parse userinfo: {e}")
        return redirect_with_msg(redirect_url, OrcidMsg.authz_error)

    if userinfo.sub != id_token["sub"]:
        current_app.logger.error(
            f"The 'sub' of userinfo does not match 'sub' of ID Token for user {proofing_state.eppn}."
        )
        return redirect_with_msg(redirect_url, OrcidMsg.sub_mismatch)

    # Save orcid and oidc data to user
    current_app.logger.info("Saving ORCID data for user")
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    oidc_id_token = OidcIdToken(
        iss=id_token["iss"],
        sub=id_token["sub"],
        aud=id_token["aud"],
        exp=id_token["exp"],
        iat=id_token["iat"],
        nonce=id_token["nonce"],
        auth_time=id_token["auth_time"],
        created_by="orcid",
    )
    oidc_authz = OidcAuthorization(
        access_token=token_resp["access_token"],
        token_type=token_resp["token_type"],
        id_token=oidc_id_token,
        expires_in=token_resp["expires_in"],
        refresh_token=token_resp["refresh_token"],
        created_by="orcid",
    )
    orcid_element = Orcid(
        id=userinfo.orcid,
        name=userinfo.name,
        given_name=userinfo.given_name,
        family_name=userinfo.family_name,
        is_verified=True,
        oidc_authz=oidc_authz,
        created_by="orcid",
    )
    orcid_proofing = OrcidProofing(
        eppn=proofing_user.eppn,
        created_by="orcid",
        orcid=orcid_element.id,
        issuer=orcid_element.oidc_authz.id_token.iss,
        audience=orcid_element.oidc_authz.id_token.aud,
        proofing_method="oidc",
        proofing_version="2018v1",
    )

    _error = True
    _msg: TranslatableMsg = CommonMsg.temp_problem

    if current_app.proofing_log.save(orcid_proofing):
        current_app.logger.info("ORCID proofing data saved to log")
        proofing_user.orcid = orcid_element
        save_and_sync_user(proofing_user)
        current_app.logger.info("ORCID proofing data saved to user")
        _error = False
        _msg = OrcidMsg.authz_success
    else:
        current_app.logger.info("ORCID proofing data NOT saved, failed to save proofing log")

    # Clean up
    current_app.logger.info("Removing proofing state")
    current_app.proofing_statedb.remove_state(proofing_state)
    return redirect_with_msg(redirect_url, msg=_msg, error=_error)


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
