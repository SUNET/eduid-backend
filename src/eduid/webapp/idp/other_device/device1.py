import base64
import logging
from datetime import datetime
from io import BytesIO
from typing import Any, Mapping, Optional, Union

import nacl
import nacl.encoding
import nacl.secret
import nacl.utils
import qrcode
from nacl.secret import SecretBox

from eduid.common.utils import urlappend
from eduid.webapp.common.api.messages import FluxData, error_response
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance_data import UsedWhere
from eduid.webapp.idp.helpers import IdPMsg
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.login_context import LoginContext
from eduid.webapp.idp.other_device.data import OtherDeviceState
from eduid.webapp.idp.other_device.db import OtherDevice
from eduid.webapp.idp.sso_session import SSOSession, record_authentication

logger = logging.getLogger(__name__)


def device1_check_response_code(
    response_code: Optional[str], sso_session: Optional[SSOSession], state: OtherDevice, ticket: LoginContext
) -> Union[Optional[SSOSession], FluxData]:
    """
    Validate the response code supplied by the user on device 1.

    The response code is given to the user on device 2 after successful authentication, in case
    device 1 was not a known device.
    """
    _accept_login = False
    if ticket.known_device and ticket.known_device.data.eppn == state.eppn:
        logger.debug("The OtherDevice state eppn matches this known devices eppn, not requiring response code")
        _accept_login = True
    elif state.device2.response_code and response_code == state.device2.response_code:
        logger.debug("The correct response code was provided")
        _accept_login = True

    if state.state == OtherDeviceState.AUTHENTICATED and _accept_login:
        if not state.eppn:
            logger.warning(f"Login using other device: No eppn in state {state.state_id}")
            logger.debug(f"Extra debug: Full other device state:\n{state.to_json()}")
            return error_response(message=IdPMsg.general_failure)

        # Clear this first, so that if something fail below the user can always reset
        ticket.set_other_device_state(None)
        state.state = OtherDeviceState.FINISHED

        sso_session = device1_login_user_from_device2(state, ticket, sso_session)

        current_app.stats.count("login_using_other_device_finished")
    else:
        if state.state != OtherDeviceState.AUTHENTICATED:
            logger.info(f"Not validating response code for use other device in state {state.state}")
        else:
            logger.info("Use other device: Incorrect response_code")
        current_app.stats.count("login_using_other_device_incorrect_code")
        state.bad_attempts += 1

    if state.state != OtherDeviceState.DENIED:
        if state.bad_attempts >= current_app.conf.other_device_max_code_attempts:
            logger.info("Use other device: too many response code attempts")
            current_app.stats.count("login_using_other_device_denied")
            state.state = OtherDeviceState.DENIED

    if not current_app.other_device_db.save(state):
        logger.warning(f"Login using other device: Failed saving state {state}")
        return error_response(message=IdPMsg.general_failure)

    return sso_session


def device1_login_user_from_device2(
    state: OtherDevice, ticket: LoginContext, sso_session: Optional[SSOSession]
) -> SSOSession:
    """
    Copy the credentials used for authentication on device 2 into the SSO session
    on this device (1). If there was no SSO session on device 1, it is created.
    """
    if not state.eppn:
        # this is really checked before this function is called, but mypy doesn't trust that
        raise RuntimeError("No eppn in OtherDevice state")

    # Process list of used credentials. Credentials inherited from an SSO session on device #2 get
    # added to the SSO session updated/created below, and request credentials (meaning ones actually
    # used during this authn, albeit on the other device, device #2) should also get added to the
    # pending request here on device #1.
    _sso_credentials_used: list[AuthnData] = []
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
    logger.info(
        f"Transferred {_request_count} request credentials used to login ref {ticket.request_ref}, "
        f"and {len(_sso_credentials_used)} to SSO session {sso_session.session_id}"
    )
    logger.debug(f"Saving SSO session {sso_session}")
    current_app.sso_sessions.save(sso_session)
    return sso_session


def device1_state_to_flux_payload(state: OtherDevice, now: datetime) -> Mapping[str, Any]:
    """Used at the end of use_other_1 to update the state in the frontend to match that of the backend."""
    if not current_app.conf.other_device_url:
        # TODO: make this config non-optional once we've finished developing this functionality
        raise RuntimeError("Missing configuration other_device_url")

    secret_box = SecretBox(nacl.encoding.URLSafeBase64Encoder.decode(current_app.conf.other_device_secret_key.encode()))
    encrypted_state_id = secret_box.encrypt(
        state.state_id.encode(), encoder=nacl.encoding.URLSafeBase64Encoder
    ).decode()

    payload: dict[str, Any] = {}
    if state.state in [OtherDeviceState.NEW, OtherDeviceState.IN_PROGRESS, OtherDeviceState.AUTHENTICATED]:
        # Only add QR code when it will actually be displayed
        buf = BytesIO()
        qr_url = urlappend(current_app.conf.other_device_url, encrypted_state_id)
        qrcode.make(qr_url).save(buf)
        qr_b64 = base64.b64encode(buf.getvalue())

        logger.debug(f"Use-other URL: {qr_url} (QR: {len(qr_b64)} bytes)")
        payload.update(
            {
                "qr_url": qr_url,  # shown in non-production environments
                "qr_img": f'data:image/png;base64, {qr_b64.decode("ascii")}',
            }
        )

    # passing expires_at to the frontend would require clock sync to be usable,
    # while passing number of seconds left is pretty unambiguous
    expires_in = int((state.expires_at - now).total_seconds())

    payload.update(
        {
            "bad_attempts": state.bad_attempts,
            "expires_in": expires_in,
            "expires_max": current_app.conf.other_device_logins_ttl.total_seconds(),
            "response_code_required": not state.device1.is_known_device,
            "short_code": state.display_id,
            "state": state.state.value,
            "state_id": encrypted_state_id,
        }
    )
    # NOTE: It is CRITICAL to never return the response code to Device #1
    return payload
