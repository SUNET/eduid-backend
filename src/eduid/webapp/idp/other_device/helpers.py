from dataclasses import dataclass
from typing import Optional

from eduid.webapp.common.api.messages import FluxData, error_response
from eduid.webapp.common.session.namespaces import IdP_OtherDevicePendingRequest, RequestRef
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.helpers import IdPMsg
from eduid.webapp.idp.login import get_ticket
from eduid.webapp.idp.login_context import LoginContext
from eduid.webapp.idp.other_device.db import OtherDevice
from eduid.webapp.idp.service import SAMLQueryParams


@dataclass
class OtherDeviceRefResult:
    response: Optional[FluxData] = None
    ticket: Optional[LoginContext] = None
    state: Optional[OtherDevice] = None


def _get_other_device_state_using_ref(ref: RequestRef, device: int) -> OtherDeviceRefResult:
    """Look for existing OtherDevice state using a login ref"""
    _info = SAMLQueryParams(request_ref=ref)
    ticket = get_ticket(_info, None)
    if not ticket:
        return OtherDeviceRefResult(response=error_response(message=IdPMsg.bad_ref))
    current_app.logger.debug(f"Extra debug: LoginContext: {ticket.dict()}")
    current_app.logger.debug(f"Extra debug: Pending request: {ticket.pending_request}")

    # Check both callers opinion of what device this is, and the states. Belts and bracers.
    if device == 1 or ticket.is_other_device_1:
        if isinstance(ticket.pending_request, IdP_OtherDevicePendingRequest):
            current_app.logger.warning("Not allowing recursive login using another device")
            return OtherDeviceRefResult(response=error_response(message=IdPMsg.not_available))
    elif device == 2 or ticket.is_other_device_2:
        if not isinstance(ticket.pending_request, IdP_OtherDevicePendingRequest):
            current_app.logger.warning("The pending request is not an IdP_OtherDevicePendingRequest")
            return OtherDeviceRefResult(response=error_response(message=IdPMsg.not_available))

    state = None
    if ticket.other_device_state_id:
        current_app.logger.debug(f"Looking for other device state using id from ticket: {ticket.other_device_state_id}")
        # Retrieve OtherDevice state. It might be expired though, in case we just create a new one.
        state = current_app.other_device_db.get_state_by_id(ticket.other_device_state_id)
        if not state:
            current_app.logger.info("OtherDevice state not found, clearing it")
            ticket.set_other_device_state(None)

    if state:
        current_app.logger.info(f"Loaded other device state: {state.state_id}")
        current_app.logger.debug(f"Extra debug: Full other device state:\n{state.to_json()}")

    return OtherDeviceRefResult(ticket=ticket, state=state)
