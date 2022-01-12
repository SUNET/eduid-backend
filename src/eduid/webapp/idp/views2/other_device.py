import base64
from dataclasses import asdict, dataclass
from io import BytesIO
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

import qrcode
import user_agents
from flask import Blueprint, jsonify, request
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.misc.timeutil import utc_now
from eduid.common.utils import urlappend
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.models import FluxSuccessResponse
from eduid.webapp.common.session import session
from eduid.webapp.common.session.logindata import LoginContext
from eduid.webapp.common.session.namespaces import IdP_OtherDevicePendingRequest, RequestRef
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance import AuthnState
from eduid.webapp.idp.assurance_data import UsedWhere
from eduid.webapp.idp.helpers import IdPMsg
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.login import get_ticket
from eduid.webapp.idp.mischttp import set_sso_cookie
from eduid.webapp.idp.other_device import OtherDevice
from eduid.webapp.idp.other_device_data import OtherDeviceId, OtherDeviceState
from eduid.webapp.idp.schemas import (
    UseOther1RequestSchema,
    UseOther1ResponseSchema,
    UseOther2RequestSchema,
    UseOther2ResponseSchema,
)
from eduid.webapp.idp.service import SAMLQueryParams
from eduid.webapp.idp.sso_session import record_authentication
from eduid.webapp.idp.util import get_ip_proximity

other_device_views = Blueprint('other_device', __name__, url_prefix='', template_folder='templates')


@other_device_views.route('/use_other_1', methods=['POST'])
@UnmarshalWith(UseOther1RequestSchema)
@MarshalWith(UseOther1ResponseSchema)
def use_other_1(
    ref: RequestRef, username: Optional[str] = None, action: Optional[str] = None, response_code: Optional[str] = None
) -> Union[FluxData, WerkzeugResponse]:
    """
    The user requests to start a "Login using another device" flow.

    This function sets up a new state for that in the database, and returns a QR code with a reference to that state.

    The QR code is the transferred (by the user) to another device (device #2), where the actual use of credentials
    will take place. The state will then be updated with the authentication information, and the user can
    retrieve them again on this device (device #1).
    """
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- Use Other Device #1 ({ref}, username {username}, action {action}) ---')

    if not current_app.conf.allow_other_device_logins or not current_app.conf.other_device_url:
        return error_response(message=IdPMsg.not_available)

    _lookup_result = _get_other_device_state_using_ref(ref, device=1)
    if _lookup_result.response:
        return _lookup_result.response

    ticket = _lookup_result.ticket
    state = _lookup_result.state
    # ensure mypy
    assert ticket

    sso_session = current_app._lookup_sso_session()

    if not state and (not action or action == 'FETCH'):
        if sso_session:
            username = sso_session.eppn
        user = None
        if username:
            user = current_app.authn.userdb.lookup_user(username)

        current_app.logger.debug(f'Adding new use other device state')
        state = current_app.other_device_db.add_new_state(ticket, user, ttl=current_app.conf.other_device_logins_ttl)
        ticket.set_other_device_state(state.state_id)
        if state.eppn:
            current_app.stats.count('login_using_other_device_start_with_eppn')
        else:
            current_app.stats.count('login_using_other_device_start_anonymous')
        current_app.logger.info(f'Added new use other device state: {state.state_id}')

    if not state:
        current_app.logger.info(f'Login using other device: State not found, or not added')
        return error_response(message=IdPMsg.state_not_found)

    now = utc_now()
    # passing expires_at to the frontend would require clock sync to be usable,
    # while passing number of seconds left is pretty unambiguous
    expires_in = (state.expires_at - now).total_seconds()

    payload: Dict[str, Any] = {}

    if state.expires_at > now:
        if action == 'FETCH':
            pass
        elif action == 'ABORT':
            if state.state in [OtherDeviceState.NEW, OtherDeviceState.IN_PROGRESS]:
                current_app.logger.info('Aborting login using another device')
                _state = current_app.other_device_db.abort(state)
                if not _state:
                    current_app.logger.warning(f'Login using other device: Failed aborting state {state}')
                    return error_response(message=IdPMsg.general_failure)
                state = _state
                current_app.stats.count('login_using_other_device_abort')
                ticket.set_other_device_state(None)
                expires_in = 0
            else:
                current_app.logger.info(f'Not aborting use other device in state {state.state}')
        elif action == 'SUBMIT_CODE':
            if state.state in [OtherDeviceState.LOGGED_IN]:
                if response_code == state.device2.response_code:
                    if not state.eppn:
                        current_app.logger.warning(f'Login using other device: No eppn in state {state.state_id}')
                        current_app.logger.debug(f'Extra debug: Full other device state:\n{state.to_json()}')
                        return error_response(message=IdPMsg.general_failure)

                    # Clear this first, so that if something fail below the user can always reset
                    state.state = OtherDeviceState.FINISHED
                    ticket.set_other_device_state(None)

                    # Process list of used credentials. Credentials inherited from an SSO session on device #2 get
                    # added to the SSO session updated/created below, and request credentials (meaning ones actually
                    # used during this authn, albeit on the other device, device #2) should also get added to the
                    # pending request here on device #1.
                    _sso_credentials_used: List[AuthnData] = []
                    _request_count = 0
                    for this in state.device2.credentials_used:
                        authn = AuthnData(cred_id=this.credential_id, timestamp=this.ts)
                        _sso_credentials_used += [authn]
                        if this.source == UsedWhere.REQUEST:
                            ticket.pending_request.credentials_used[this.credential_id] = this.ts
                            _request_count += 1

                    # Create/update SSO session
                    sso_session = record_authentication(
                        ticket, state.eppn, sso_session, _sso_credentials_used, current_app.conf.sso_session_lifetime
                    )

                    current_app.logger.info(
                        f'Transferred {_request_count} request credentials used to login ref {ticket.request_ref}, '
                        f'and {len(_sso_credentials_used)} to SSO session {sso_session.session_id}'
                    )

                    current_app.logger.debug(f'Saving SSO session {sso_session}')
                    current_app.sso_sessions.save(sso_session)

                    current_app.stats.count('login_using_other_device_finished')
                else:
                    current_app.logger.info(f'Use other device: Incorrect response_code')
                    current_app.stats.count('login_using_other_device_incorrect_code')
                    state.bad_attempts += 1
            else:
                current_app.logger.info(f'Not validating response code for use other device in state {state.state}')
                state.bad_attempts += 1

            if state.state != OtherDeviceState.DENIED:
                if state.bad_attempts >= current_app.conf.other_device_max_code_attempts:
                    current_app.logger.info(f'Use other device: too many response code attempts')
                    current_app.stats.count('login_using_other_device_denied')
                    state.state = OtherDeviceState.DENIED

            if not current_app.other_device_db.save(state):
                current_app.logger.warning(f'Login using other device: Failed saving state {state}')
                return error_response(message=IdPMsg.general_failure)
        elif action is not None:
            current_app.logger.error(f'Login using other device: Unknown action: {action}')
            return error_response(message=IdPMsg.general_failure)
    else:
        age = int((now - state.expires_at).total_seconds())
        current_app.logger.info(f'Use other device state is expired ({age} seconds)')

    if state.state in [OtherDeviceState.NEW, OtherDeviceState.IN_PROGRESS, OtherDeviceState.LOGGED_IN]:
        # Only add QR code when it will actually be displayed
        buf = BytesIO()
        qr_url = urlappend(current_app.conf.other_device_url, str(state.state_id))
        qrcode.make(qr_url).save(buf)
        qr_b64 = base64.b64encode(buf.getvalue())

        current_app.logger.debug(f'Use-other URL: {qr_url} (QR: {len(qr_b64)} bytes)')
        payload.update(
            {
                'qr_url': qr_url,  # shown in non-production environments
                'qr_img': f'data:image/png;base64, {qr_b64.decode("ascii")}',
            }
        )

    payload.update(
        {
            'expires_max': current_app.conf.other_device_logins_ttl.total_seconds(),
            'state_id': state.state_id,  # TODO: Make a secretbox with the state_id in it here
            'state': state.state.value,
            'short_code': state.short_code,
            'expires_in': expires_in,
        }
    )

    # NOTE: It is CRITICAL to never return the response code to Device #1
    if sso_session:
        # In case we created the SSO session above, we need to return it's ID to the user in a cookie
        _flux_response = FluxSuccessResponse(request, payload=payload)
        resp = jsonify(UseOther1ResponseSchema().dump(_flux_response.to_dict()))

        return set_sso_cookie(sso_session.session_id, resp)

    return success_response(payload=payload)


@other_device_views.route('/use_other_2', methods=['POST'])
@UnmarshalWith(UseOther2RequestSchema)
@MarshalWith(UseOther2ResponseSchema)
def use_other_2(ref: Optional[RequestRef], state_id: Optional[OtherDeviceId]) -> FluxData:
    """ "Login using another device" flow.

    This is the first step on device #2. When the user has scanned the QR code, the frontend will fetch state
    using this endpoint.
    """
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- Use Other Device #2 (ref {ref}, state_id {state_id}) ---')

    if not current_app.conf.allow_other_device_logins:
        return error_response(message=IdPMsg.not_available)

    state = None

    if ref:
        _lookup_result = _get_other_device_state_using_ref(ref, device=2)
        if _lookup_result.response:
            return _lookup_result.response

        state = _lookup_result.state
    elif state_id:
        # Load state using state_id from QR URL
        current_app.logger.debug(f'Other device: Loading state using state_id: {state_id} (from QR code)')
        state = current_app.other_device_db.get_state_by_id(state_id)
        if not state:
            current_app.logger.debug(f'Other device: State with state_id {state_id} (from QR code) not found')
        else:
            current_app.logger.info(f'Loaded other device state: {state.state_id}')
            current_app.logger.debug(f'Extra debug: Full other device state:\n{state.to_json()}')

    if not state:
        current_app.logger.debug(f'Other device: No state found, bailing out')
        return error_response(message=IdPMsg.state_not_found)

    if state.state == OtherDeviceState.NEW:
        # Grab this state and associate it with the current browser session. This is important so that
        # it's not possible for an attacker to initiate other device, send QR code to victim, have them
        # use it and log in and then use the QR code to retrieve the response code.
        request_ref = RequestRef(str(uuid4()))
        _state = current_app.other_device_db.grab(state, request_ref)
        if not _state:
            current_app.logger.warning(f'Failed to grab state: {state.state_id}')
            return error_response(message=IdPMsg.general_failure)
        current_app.logger.info(f'Grabbed login with other device state {state.state_id}')
        state = _state
        pending = IdP_OtherDevicePendingRequest(state_id=state.state_id)
        session.idp.pending_requests[request_ref] = pending
        current_app.logger.debug(f'Created new pending request with ref {request_ref}: {pending}')

    if ref and state.device2.ref != ref:
        current_app.logger.warning(
            f'Tried to use OtherDevice state that is not ours: {state.device2.ref} != {ref} (ours)'
        )
        current_app.logger.debug(f'Extra debug: Full other device state:\n{state.to_json()}')
        return error_response(message=IdPMsg.general_failure)  # TODO: make a real error code for this

    # passing expires_at to the frontend would require clock sync to be usable,
    # while passing number of seconds left is pretty unambiguous
    now = utc_now()
    expires_in = (state.expires_at - now).total_seconds()

    # The frontend will present the user with the option to proceed with this login on this device #2.
    # If the user proceeds, the frontend can now call the /next endpoint with the ref returned in this response.
    device_info = {
        'addr': state.device1.ip_address,
        'description': str(user_agents.parse(state.device1.user_agent)),
        'proximity': get_ip_proximity(state.device1.ip_address, request.remote_addr).value,
    }

    payload: Dict[str, Any] = {
        'device1_info': device_info,
        'expires_in': expires_in,
        'expires_max': current_app.conf.other_device_logins_ttl.total_seconds(),
        'login_ref': state.device2.ref,
        'short_code': state.short_code,
        'state': state.state.value,
    }

    if state.state == OtherDeviceState.LOGGED_IN:
        # Be very explicit about when response_code is returned.
        payload['response_code'] = state.device2.response_code
    else:
        # This really shouldn't happen, but better ensure it like this.
        if 'response_code' in payload:
            current_app.logger.error(f'Response code found in use other device state {state.state} payload - removing')
            del payload['response_code']

    return success_response(payload=payload)


@dataclass
class OtherDeviceRefResult:
    response: Optional[FluxData] = None
    ticket: Optional[LoginContext] = None
    state: Optional[OtherDevice] = None


def _get_other_device_state_using_ref(ref: RequestRef, device: int) -> OtherDeviceRefResult:
    """ Look for existing OtherDevice state using a login ref """
    _info = SAMLQueryParams(request_ref=ref)
    ticket = get_ticket(_info, None)
    if not ticket:
        return OtherDeviceRefResult(response=error_response(message=IdPMsg.bad_ref))
    current_app.logger.debug(f'Extra debug: LoginContext: {asdict(ticket)}')
    current_app.logger.debug(f'Extra debug: Pending request: {ticket.pending_request}')

    # Check both callers opinion of what device this is, and the states. Belts and bracers.
    if device == 1 or ticket.is_other_device == 1:
        if isinstance(ticket.pending_request, IdP_OtherDevicePendingRequest):
            current_app.logger.warning(f'Not allowing recursive login using another device')
            return OtherDeviceRefResult(response=error_response(message=IdPMsg.not_available))
    elif device == 2 or ticket.is_other_device == 2:
        if not isinstance(ticket.pending_request, IdP_OtherDevicePendingRequest):
            current_app.logger.warning(f'The pending request is not an IdP_OtherDevicePendingRequest')
            return OtherDeviceRefResult(response=error_response(message=IdPMsg.not_available))

    state = None
    if ticket.other_device_state_id:
        current_app.logger.debug(f'Looking for other device state using id from ticket: {ticket.other_device_state_id}')
        # Retrieve OtherDevice state. It might be expired though, in case we just create a new one.
        state = current_app.other_device_db.get_state_by_id(ticket.other_device_state_id)
        if not state:
            current_app.logger.info('OtherDevice state not found, clearing it')
            ticket.set_other_device_state(None)

    if state:
        current_app.logger.info(f'Loaded other device state: {state.state_id}')
        current_app.logger.debug(f'Extra debug: Full other device state:\n{state.to_json()}')

    return OtherDeviceRefResult(ticket=ticket, state=state)
