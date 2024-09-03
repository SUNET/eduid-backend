from typing import Optional, Union
from uuid import uuid4

import nacl
import nacl.encoding
import nacl.secret
import nacl.utils
from flask import Blueprint, jsonify, request
from nacl.secret import SecretBox
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.exceptions import UserDoesNotExist
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.models import FluxSuccessResponse
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import IdP_OtherDevicePendingRequest, RequestRef
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.decorators import require_ticket, uses_sso_session
from eduid.webapp.idp.helpers import IdPMsg, lookup_user
from eduid.webapp.idp.login_context import LoginContext
from eduid.webapp.idp.mischttp import set_sso_cookie
from eduid.webapp.idp.other_device.data import OtherDeviceId, OtherDeviceState
from eduid.webapp.idp.other_device.device1 import device1_check_response_code, device1_state_to_flux_payload
from eduid.webapp.idp.other_device.device2 import device2_state_to_flux_payload
from eduid.webapp.idp.other_device.helpers import _get_other_device_state_using_ref
from eduid.webapp.idp.schemas import (
    UseOther1RequestSchema,
    UseOther1ResponseSchema,
    UseOther2RequestSchema,
    UseOther2ResponseSchema,
)
from eduid.webapp.idp.sso_session import SSOSession
from eduid.webapp.idp.views.next import get_required_user

other_device_views = Blueprint("other_device", __name__, url_prefix="")


@other_device_views.route("/use_other_1", methods=["POST"])
@UnmarshalWith(UseOther1RequestSchema)
@MarshalWith(UseOther1ResponseSchema)
@require_ticket
@uses_sso_session
def use_other_1(
    ticket: LoginContext,
    sso_session: Optional[SSOSession],
    username: Optional[str] = None,
    action: Optional[str] = None,
    response_code: Optional[str] = None,
) -> Union[FluxData, WerkzeugResponse]:
    """
    The user requests to start a "Login using another device" flow.

    This function sets up a new state for that in the database, and returns a QR code with a reference to that state.

    The QR code is the transferred (by the user) to another device (device #2), where the actual use of credentials
    will take place. The state will then be updated with the authentication information, and the user can
    retrieve them again on this device (device #1).
    """
    current_app.logger.debug("\n\n")
    current_app.logger.debug(
        f"--- Use Other Device #1 ({ticket.request_ref}, username {username}, action {action}) ---"
    )

    if not current_app.conf.allow_other_device_logins or not current_app.conf.other_device_url:
        return error_response(message=IdPMsg.not_available)

    _lookup_result = _get_other_device_state_using_ref(ticket.request_ref, device=1)
    if _lookup_result.response:
        return _lookup_result.response

    state = _lookup_result.state

    now = utc_now()  # ensure coherent results of 'is this expired?' checks

    if not state or action in [None, "FETCH"]:
        # If the user is using a known device, or has an SSO session, or the SP requests a certain user,
        # that requirement is passed into the OtherDevice state (by setting state.eppn).
        required_user = get_required_user(ticket, sso_session)
        if required_user.response:
            return required_user.response

        user = None
        if required_user.eppn:
            try:
                user = current_app.userdb.get_user_by_eppn(required_user.eppn)
            except UserDoesNotExist:
                current_app.logger.info(
                    f"Login using other device: User {required_user.eppn} does not exist in central db"
                )
                return error_response(message=IdPMsg.wrong_user)
        elif username:
            user = lookup_user(username)

        current_app.logger.debug(f"Adding new use other device state (user: {user})")
        state = current_app.other_device_db.add_new_state(ticket, user, ttl=current_app.conf.other_device_logins_ttl)
        ticket.set_other_device_state(state.state_id)
        if state.eppn:
            current_app.stats.count("login_using_other_device_start_with_eppn")
        else:
            current_app.stats.count("login_using_other_device_start_anonymous")
        current_app.logger.info(f"Added new use other device state: {state.state_id}")

        payload = device1_state_to_flux_payload(state, now)
        return success_response(payload=payload)

    if not state:
        current_app.logger.info("Login using other device: State not found")
        return error_response(message=IdPMsg.state_not_found)

    if state.expires_at <= now:
        age = int((now - state.expires_at).total_seconds())
        current_app.logger.info(f"Login using other device: State is expired ({age} seconds ago)")
        payload = device1_state_to_flux_payload(state, now)
        return success_response(payload=payload)

    #
    # The frontend can provide an action to modify an existing state. Handle those below.
    #

    if action == "ABORT":
        if state.state in [OtherDeviceState.NEW, OtherDeviceState.IN_PROGRESS]:
            current_app.logger.info("Aborting login using another device")
            _abort_res = current_app.other_device_db.abort(state)
            if not _abort_res:
                current_app.logger.warning(f"Login using other device: Failed aborting state {state}")
                return error_response(message=IdPMsg.general_failure)
            state = _abort_res
            current_app.stats.count("login_using_other_device_abort_device1")
            ticket.set_other_device_state(None)
        else:
            current_app.logger.info(f"Not aborting use other device in state {state.state}")

    elif action == "SUBMIT_CODE":
        _submit_res = device1_check_response_code(response_code, sso_session, state, ticket)
        if isinstance(_submit_res, FluxData):
            return _submit_res
        sso_session = _submit_res

    else:
        current_app.logger.error(f"Login using other device: Unknown action: {action}")
        return error_response(message=IdPMsg.general_failure)

    payload = device1_state_to_flux_payload(state, now)

    if sso_session:
        # In case we created the SSO session above, we need to return its ID to the user in a cookie
        _flux_response = FluxSuccessResponse(request, payload=payload)
        resp = jsonify(UseOther1ResponseSchema().dump(_flux_response.to_dict()))

        return set_sso_cookie(current_app.conf.sso_cookie, sso_session.session_id, resp)

    return success_response(payload=payload)


@other_device_views.route("/use_other_2", methods=["POST"])
@UnmarshalWith(UseOther2RequestSchema)
@MarshalWith(UseOther2ResponseSchema)
@uses_sso_session
def use_other_2(
    ref: Optional[RequestRef],
    state_id: Optional[OtherDeviceId],
    sso_session: Optional[SSOSession],
    action: Optional[str] = None,
) -> FluxData:
    """ "Login using another device" flow.

    This is the first step on device #2. When the user has scanned the QR code, the frontend will fetch state
    using this endpoint.
    """
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- Use Other Device #2 (ref {ref}, state_id {state_id}) ---")

    if not current_app.conf.allow_other_device_logins:
        return error_response(message=IdPMsg.not_available)

    state = None

    if ref:
        _lookup_result = _get_other_device_state_using_ref(ref, device=2)
        if _lookup_result.response:
            return _lookup_result.response

        state = _lookup_result.state
    elif state_id:
        secret_box = SecretBox(
            nacl.encoding.URLSafeBase64Encoder.decode(current_app.conf.other_device_secret_key.encode())
        )
        decrypted = secret_box.decrypt(state_id.encode(), encoder=nacl.encoding.URLSafeBase64Encoder).decode()

        # Load state using state_id from QR URL
        current_app.logger.debug(f"Other device: Loading state using state_id: {decrypted} (from QR code)")
        state = current_app.other_device_db.get_state_by_id(OtherDeviceId(decrypted))
        if not state:
            current_app.logger.debug(f"Other device: State with state_id {decrypted} (from QR code) not found")
        else:
            current_app.logger.info(f"Loaded other device state: {state.state_id}")
            current_app.logger.debug(f"Extra debug: Full other device state:\n{state.to_json()}")

    if not state:
        current_app.logger.debug("Other device: No state found, bailing out")
        return error_response(message=IdPMsg.state_not_found)

    now = utc_now()  # ensure coherent results of 'is this expired?' checks
    if state.expires_at <= now:
        age = int((now - state.expires_at).total_seconds())
        current_app.logger.info(f"Login using other device: State is expired ({age} seconds ago)")
        payload = device2_state_to_flux_payload(state, now)
        return success_response(payload=payload)

    if state.state == OtherDeviceState.NEW:
        # Grab this state and associate it with the current browser session. This is important so that
        # it's not possible for an attacker to initiate other device, send QR code to victim, have them
        # use it and log in and then use the QR code to retrieve the response code.
        request_ref = RequestRef(str(uuid4()))

        if sso_session:
            if sso_session.eppn != state.eppn:
                current_app.logger.warning(
                    f"Can't login as eppn {state.eppn} on this device, "
                    "SSO session has another eppn: {sso_session.eppn}"
                )
                return error_response(message=IdPMsg.wrong_user)

        _state = current_app.other_device_db.grab(state, request_ref)
        if not _state:
            current_app.logger.warning(f"Failed to grab state: {state.state_id}")
            return error_response(message=IdPMsg.general_failure)
        current_app.logger.info(f"Grabbed login with other device state {state.state_id}")
        state = _state
        pending = IdP_OtherDevicePendingRequest(state_id=state.state_id)
        session.idp.pending_requests[request_ref] = pending
        current_app.logger.debug(f"Created new pending request with ref {request_ref}: {pending}")
    else:
        # Could be a reload of the page on device #2, or it could be an attacker opening the QR code on one
        # device, and wanting the user to open it again on their device and log them (the attacker) in.
        # If it is a reload, the state.ref should be present in the session as a pending_request.
        if state.device2.ref not in session.idp.pending_requests:
            current_app.logger.warning(
                f"Tried to use OtherDevice state that is already in use: {state.device2.ref} (not found in session)"
            )
            current_app.logger.debug(f"Extra debug: Full other device state:\n{state.to_json()}")
            return error_response(message=IdPMsg.state_already_used)

    if action == "ABORT":
        if state.state in [OtherDeviceState.NEW, OtherDeviceState.IN_PROGRESS, OtherDeviceState.AUTHENTICATED]:
            current_app.logger.info("Aborting login using another device")
            _abort_res = current_app.other_device_db.abort(state)
            if not _abort_res:
                current_app.logger.warning(f"Login using other device: Failed aborting state {state}")
                return error_response(message=IdPMsg.general_failure)
            state = _abort_res
            current_app.stats.count("login_using_other_device_abort_device2")
        else:
            current_app.logger.info(f"Not aborting use other device in state {state.state}")

    payload = device2_state_to_flux_payload(state, now)

    return success_response(payload=payload)
