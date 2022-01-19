import base64
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List, Mapping, Optional, Union

import qrcode

from eduid.common.utils import urlappend
from eduid.webapp.common.api.messages import FluxData, error_response
from eduid.webapp.common.session.logindata import LoginContext
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance_data import UsedWhere
from eduid.webapp.idp.helpers import IdPMsg
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.other_device.data import OtherDeviceState
from eduid.webapp.idp.other_device.db import OtherDevice
from eduid.webapp.idp.sso_session import SSOSession, record_authentication


def _device1_check_response_code(
    response_code: Optional[str], sso_session: Optional[SSOSession], state: OtherDevice, ticket: LoginContext
) -> Union[Optional[SSOSession], FluxData]:
    if state.state != OtherDeviceState.LOGGED_IN:
        current_app.logger.info(f'Not validating response code for use other device in state {state.state}')
        state.bad_attempts += 1
        if not current_app.other_device_db.save(state):
            current_app.logger.warning(f'Login using other device: Failed saving state {state}')
        return error_response(message=IdPMsg.general_failure)

    if state.device2.response_code and response_code == state.device2.response_code:
        if not state.eppn:
            current_app.logger.warning(f'Login using other device: No eppn in state {state.state_id}')
            current_app.logger.debug(f'Extra debug: Full other device state:\n{state.to_json()}')
            return error_response(message=IdPMsg.general_failure)

        # Clear this first, so that if something fail below the user can always reset
        ticket.set_other_device_state(None)
        state.state = OtherDeviceState.FINISHED

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

    if state.state != OtherDeviceState.DENIED:
        if state.bad_attempts >= current_app.conf.other_device_max_code_attempts:
            current_app.logger.info(f'Use other device: too many response code attempts')
            current_app.stats.count('login_using_other_device_denied')
            state.state = OtherDeviceState.DENIED

    if not current_app.other_device_db.save(state):
        current_app.logger.warning(f'Login using other device: Failed saving state {state}')
        return error_response(message=IdPMsg.general_failure)

    return sso_session


def _device1_state_to_flux_payload(state: OtherDevice, now: datetime) -> Mapping[str, Any]:
    if not current_app.conf.other_device_url:
        # TODO: make this config non-optional once we've finished developing this functionality
        raise RuntimeError('Missing configuration other_device_url')

    payload: Dict[str, Any] = {}
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

    # passing expires_at to the frontend would require clock sync to be usable,
    # while passing number of seconds left is pretty unambiguous
    expires_in = int((state.expires_at - now).total_seconds())

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
    return payload
