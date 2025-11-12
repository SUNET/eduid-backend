import logging
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from flask import request, url_for

from eduid.common.misc.timeutil import utc_now
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance import AuthnState
from eduid.webapp.idp.helpers import IdPAction, IdPMsg, lookup_user
from eduid.webapp.idp.login_context import LoginContextOtherDevice
from eduid.webapp.idp.other_device.data import OtherDeviceState
from eduid.webapp.idp.other_device.db import OtherDevice
from eduid.webapp.idp.sso_session import SSOSession
from eduid.webapp.idp.util import IPProximity, get_ip_proximity, get_login_username

logger = logging.getLogger(__name__)


def device2_finish(ticket: LoginContextOtherDevice, sso_session: SSOSession, authn_state: AuthnState) -> FluxData:
    if not current_app.conf.allow_other_device_logins:
        return error_response(message=IdPMsg.not_available)

    state = ticket.other_device_req
    if state.device2.ref != ticket.request_ref:
        logger.warning(f"Tried to use OtherDevice state that is not ours: {state}")
        return error_response(message=IdPMsg.general_failure)  # TODO: make a real error code for this

    if state.expires_at < utc_now():
        current_app.stats.count("login_using_other_device_finish_too_late")
        logger.error(f"Request to login using another device was expired: {state}")
        return error_response(message=IdPMsg.other_device_expired)

    if state.state == OtherDeviceState.IN_PROGRESS:
        logger.debug(f"Recording login using another device {state.state_id} as finished")
        logger.debug(f"Extra debug: SSO eppn {sso_session.eppn}")
        _state = current_app.other_device_db.logged_in(state, sso_session.eppn, authn_state.credentials)
        if not _state:
            logger.warning(f"Failed to finish state: {state.state_id}")
            return error_response(message=IdPMsg.general_failure)
        logger.info(f"Finished login with other device state {state.state_id}")
        current_app.stats.count("login_using_other_device_finish")

    return success_response(
        message=IdPMsg.finished,
        payload={
            "action": IdPAction.FINISHED.value,
            "target": url_for("other_device.use_other_2", _external=True),
        },
    )


def device2_state_to_flux_payload(state: OtherDevice, now: datetime) -> Mapping[str, Any]:
    # passing expires_at to the frontend would require clock sync to be usable,
    # while passing number of seconds left is pretty unambiguous
    expires_in = (state.expires_at - now).total_seconds()
    # The frontend will present the user with the option to proceed with this login on this device #2.
    # If the user proceeds, the frontend can now call the /next endpoint with the ref returned in this response.

    username = None
    display_name = None

    if state.eppn:
        user = lookup_user(state.eppn)
        if user:
            display_name = user.friendly_identifier or state.eppn
            username = get_login_username(user)

    _proximity = IPProximity.FAR
    if request.remote_addr:
        _proximity = get_ip_proximity(state.device1.ip_address, request.remote_addr)

    device_info = {
        "addr": state.device1.ip_address,
        "description": state.device1.user_agent,
        "is_known_device": state.device1.is_known_device,
        "proximity": _proximity.value,
        "service_info": state.device1.service_info,
    }
    payload: dict[str, Any] = {
        "device1_info": device_info,
        "display_name": display_name,
        "expires_in": expires_in,
        "expires_max": current_app.conf.other_device_logins_ttl.total_seconds(),
        "login_ref": state.device2.ref,
        "response_code_required": not state.device1.is_known_device,
        "short_code": state.display_id,
        "state": state.state.value,
        "username": username,
    }
    if state.state == OtherDeviceState.AUTHENTICATED:
        # Be very explicit about when response_code is returned.
        payload["response_code"] = state.device2.response_code
    elif "response_code" in payload:
        # This really shouldn't happen, but better ensure it like this.
        logger.error(f"Response code found in use other device state {state.state} payload - removing")
        del payload["response_code"]
    return payload
