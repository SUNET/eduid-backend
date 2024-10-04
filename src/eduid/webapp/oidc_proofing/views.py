import base64
import binascii
from collections.abc import Mapping
from io import BytesIO
from typing import Any

import qrcode
import qrcode.image.svg
import requests
from flask import Blueprint, Response, make_response, request, url_for
from jose import jws as jose
from oic.oic.message import AuthorizationResponse, Claims, ClaimsRequest
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.rpc.exceptions import TaskFailed
from eduid.userdb import User
from eduid.userdb.exceptions import UserDoesNotExist
from eduid.userdb.proofing import ProofingUser
from eduid.userdb.util import UTC
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, can_verify_nin, require_user
from eduid.webapp.common.api.helpers import add_nin_to_user
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response
from eduid.webapp.oidc_proofing import helpers, schemas
from eduid.webapp.oidc_proofing.app import current_oidcp_app as current_app
from eduid.webapp.oidc_proofing.helpers import OIDCMsg

__author__ = "lundberg"

"""
OIDC code very inspired by https://github.com/its-dirg/Flask-pyoidc
"""

oidc_proofing_views = Blueprint("oidc_proofing", __name__, url_prefix="", template_folder="templates")


@oidc_proofing_views.route("/authorization-response")
def authorization_response() -> Response:
    # parse authentication response
    query_string = request.query_string.decode("utf-8")
    current_app.logger.debug(f"query_string: {query_string!s}")
    authn_resp = current_app.oidc_client.parse_response(AuthorizationResponse, info=query_string, sformat="urlencoded")
    current_app.logger.debug(f"Authorization response received: {authn_resp!s}")

    if authn_resp.get("error"):
        current_app.logger.error(
            "AuthorizationError from {}: {} - {} ({})".format(
                request.host, authn_resp["error"], authn_resp.get("error_message"), authn_resp.get("error_uri")
            )
        )
        current_app.stats.count(name="authn_response_op_error")
        return make_response("OK", 200)

    user_oidc_state = authn_resp["state"]
    proofing_state = current_app.proofing_statedb.get_state_by_oidc_state(user_oidc_state)
    if not proofing_state:
        msg = f"The 'state' parameter ({user_oidc_state!s}) does not match a user state."
        current_app.logger.error(msg)
        current_app.stats.count(name="authn_response_proofing_state_missing")
        return make_response("OK", 200)
    current_app.logger.debug(f"Proofing state {proofing_state.state!s} for user {proofing_state.eppn!s} found")

    # Check if the token from the authn response matches the token we created when making the auth request
    authorization_header = request.headers.get("Authorization")
    if authorization_header != f"Bearer {proofing_state.token}":
        current_app.logger.error(f"The authorization token ({authorization_header!s}) did not match the expected")
        current_app.stats.count(name="authn_response_authn_failure")
        return make_response("FORBIDDEN", 403)

    # TODO: We should save the auth response code to the proofing state to be able to continue a failed attempt
    # do token request
    args = {"code": authn_resp["code"], "redirect_uri": url_for("oidc_proofing.authorization_response", _external=True)}
    current_app.logger.debug(f"Trying to do token request: {args!s}")
    # TODO: What should be saved from the token response and where?
    token_resp = current_app.oidc_client.do_access_token_request(
        scope="openid", state=authn_resp["state"], request_args=args, authn_method="client_secret_basic"
    )
    current_app.logger.debug(f"token response received: {token_resp!s}")
    id_token = token_resp["id_token"]
    if id_token["nonce"] != proofing_state.nonce:
        current_app.logger.error(f"The 'nonce' parameter does not match for user {proofing_state.eppn!s}.")
        current_app.stats.count(name="authn_response_token_request_failure")
        return make_response("OK", 200)
    current_app.stats.count(name="authn_response_token_request_success")

    # do userinfo request
    current_app.logger.debug("Trying to do userinfo request:")
    # TODO: Do we need to save anything else from the userinfo response
    userinfo = current_app.oidc_client.do_user_info_request(
        method=current_app.conf.userinfo_endpoint_method, state=authn_resp["state"]
    )
    current_app.logger.debug(f"userinfo received: {userinfo!s}")
    if userinfo["sub"] != id_token["sub"]:
        current_app.logger.error(
            f"The 'sub' of userinfo does not match 'sub' of ID Token for user {proofing_state.eppn!s}."
        )
        current_app.stats.count(name="authn_response_userinfo_request_failure")
        return make_response("OK", 200)
    current_app.stats.count(name="authn_response_userinfo_request_success")

    # TODO: Break out in parts to be able to continue the proofing process after a successful authorization response
    #       even if the token request, userinfo request or something internal fails
    user = None
    try:
        am_user = current_app.central_userdb.get_user_by_eppn(proofing_state.eppn)
        user = ProofingUser.from_user(am_user, current_app.private_userdb)
    except UserDoesNotExist:
        current_app.logger.error(f"Failed to handle userinfo for unknown user {proofing_state.eppn}")
        current_app.stats.count(name="authn_response_unknown_user")
        current_app.proofing_statedb.remove_state(proofing_state)
        return make_response("OK", 200)

    try:
        # Handle userinfo differently depending on data in userinfo
        if userinfo.get("identity"):
            current_app.logger.info(f"Handling userinfo as generic seleg vetting for user {user}")
            current_app.stats.count(name="seleg.authn_response_received")
            helpers.handle_seleg_userinfo(user, proofing_state, userinfo)
        elif userinfo.get("results"):
            current_app.logger.info(f"Handling userinfo as freja vetting for user {user}")
            current_app.stats.count(name="freja.authn_response_received")
            helpers.handle_freja_eid_userinfo(user, proofing_state, userinfo)
    except (TaskFailed, KeyError):
        current_app.logger.exception(f"Failed to handle userinfo for user {user}")
        current_app.stats.count(name="authn_response_handling_failure")
    finally:
        # Remove users proofing state
        current_app.proofing_statedb.remove_state(proofing_state)
    return make_response("OK", 200)


@oidc_proofing_views.route("/proofing", methods=["GET"])
@MarshalWith(schemas.NonceResponseSchema)
@require_user
def get_seleg_state(user: User) -> dict[str, Any]:
    current_app.logger.debug(f"Getting state for user {user}.")
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn)
    if not proofing_state:
        return {}
    expire_time = current_app.conf.seleg_expire_time_hours
    if helpers.is_proofing_state_expired(proofing_state, expire_time):
        current_app.proofing_statedb.remove_state(proofing_state)
        current_app.stats.count(name="seleg.proofing_state_expired")
        return {}
    # Return nonce and nonce as qr code
    current_app.logger.debug(f"Returning nonce for user {user!s}")
    current_app.stats.count(name="seleg.proofing_state_returned")
    buf = BytesIO()
    qr_code = helpers.create_opaque_data(proofing_state.nonce, proofing_state.token)
    qrcode.make(qr_code).save(buf)
    qr_b64 = base64.b64encode(buf.getvalue())
    return {
        "qr_code": qr_code,
        "qr_img": f"data:image/png;base64, {qr_b64!s}",
    }


@oidc_proofing_views.route("/proofing", methods=["POST"])
@UnmarshalWith(schemas.OidcProofingRequestSchema)
@MarshalWith(schemas.NonceResponseSchema)
@can_verify_nin
@require_user
def seleg_proofing(user: User, nin: str) -> FluxData | WerkzeugResponse:
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn)
    if not proofing_state:
        current_app.logger.debug(f"No proofing state found for user {user!s}. Initializing new proofing flow.")
        proofing_state = helpers.create_proofing_state(user, nin)

        # Initiate authn request
        try:
            redirect_url = url_for("oidc_proofing.authorization_response", _external=True)
            claims_request = ClaimsRequest(userinfo=Claims(identity=None, vetting_time=None, metadata=None))
            success = helpers.do_authn_request(proofing_state, claims_request, redirect_url)
            if not success:
                current_app.stats.count(name="seleg.authn_request_op_error")
                return error_response(message=CommonMsg.temp_problem)
        except requests.exceptions.ConnectionError as e:
            current_app.logger.error(f"No connection to authorization endpoint: {e!s}")
            return error_response(message=OIDCMsg.no_conn)

        # If authentication request went well save user state
        current_app.stats.count(name="seleg.authn_request_success")
        current_app.proofing_statedb.save(proofing_state, is_in_database=False)
        current_app.logger.debug(f"Proofing state {proofing_state.state!s} for user {user!s} saved")
    # Add the nin used to initiate the proofing state to the user
    # NOOP if the user already have the nin
    add_nin_to_user(user, proofing_state)

    return get_seleg_state()


@oidc_proofing_views.route("/freja/proofing", methods=["GET"])
@MarshalWith(schemas.FrejaResponseSchema)
@require_user
def get_freja_state(user: User) -> Mapping[str, Any]:
    current_app.logger.debug(f"Getting state for user {user!s}.")
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn)
    if not proofing_state:
        return {}
    expire_time = current_app.conf.freja_expire_time_hours
    if helpers.is_proofing_state_expired(proofing_state, expire_time):
        current_app.proofing_statedb.remove_state(proofing_state)
        current_app.stats.count(name="freja.proofing_state_expired")
        return {}
    # Return request data
    current_app.logger.debug(f"Returning request data for user {user!s}")
    current_app.stats.count(name="freja.proofing_state_returned")
    opaque_data = helpers.create_opaque_data(proofing_state.nonce, proofing_state.token)
    valid_until = helpers.get_proofing_state_valid_until(proofing_state, expire_time)
    request_data = {
        "iarp": current_app.conf.freja_iarp,
        "exp": int(valid_until.astimezone(UTC()).strftime("%s")) * 1000,  # Milliseconds since 1970 in UTC
        "proto": current_app.conf.freja_response_protocol,
        "opaque": opaque_data,
    }

    jwk = binascii.unhexlify(current_app.conf.freja_jwk_secret)
    jws_header = {
        "alg": current_app.conf.freja_jws_algorithm,
        "kid": current_app.conf.freja_jws_key_id,
    }
    jws = jose.sign(request_data, jwk, headers=jws_header, algorithm=current_app.conf.freja_jws_algorithm)
    return {"iaRequestData": jws}


@oidc_proofing_views.route("/freja/proofing", methods=["POST"])
@UnmarshalWith(schemas.OidcProofingRequestSchema)
@MarshalWith(schemas.FrejaResponseSchema)
@can_verify_nin
@require_user
def freja_proofing(user: User, nin: str) -> FluxData | WerkzeugResponse:
    proofing_state = current_app.proofing_statedb.get_state_by_eppn(user.eppn)
    if not proofing_state:
        current_app.logger.debug(f"No proofing state found for user {user!s}. Initializing new proofing flow.")
        proofing_state = helpers.create_proofing_state(user, nin)

        # Initiate authn request
        try:
            redirect_url = url_for("oidc_proofing.authorization_response", _external=True)
            claims_request = ClaimsRequest(userinfo=Claims(results=None))
            success = helpers.do_authn_request(proofing_state, claims_request, redirect_url)
            if not success:
                current_app.stats.count(name="freja.authn_request_op_error")
                return error_response(message=CommonMsg.temp_problem)
        except requests.exceptions.ConnectionError as e:
            current_app.logger.error(f"No connection to authorization endpoint: {e!s}")
            return error_response(message=OIDCMsg.no_conn)

        # If authentication request went well save user state
        current_app.stats.count(name="freja.authn_request_success")
        current_app.proofing_statedb.save(proofing_state, is_in_database=False)
        current_app.logger.debug(f"Proofing state {proofing_state.state!s} for user {user!s} saved")
    # Add the nin used to initiate the proofing state to the user
    # NOOP if the user already have the nin
    add_nin_to_user(user, proofing_state)

    return get_freja_state()
