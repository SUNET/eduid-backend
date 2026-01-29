import re
from base64 import urlsafe_b64decode
from dataclasses import asdict, dataclass
from typing import Any

import requests
from cryptography.hazmat.primitives import hashes, hmac
from flask import Blueprint, request, url_for

from eduid.userdb.credentials import FidoCredential, Password
from eduid.userdb.idp import IdPUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance_data import AuthnInfo
from eduid.webapp.idp.decorators import require_ticket, uses_sso_session
from eduid.webapp.idp.helpers import IdPAction, IdPMsg, create_saml_sp_response, lookup_user
from eduid.webapp.idp.idp_saml import authn_context_class_not_supported, cancel_saml_request
from eduid.webapp.idp.login import SSO, login_next_step
from eduid.webapp.idp.login_context import LoginContext, LoginContextOtherDevice, LoginContextSAML
from eduid.webapp.idp.mischttp import get_user_agent
from eduid.webapp.idp.other_device.data import OtherDeviceState
from eduid.webapp.idp.other_device.device2 import device2_finish
from eduid.webapp.idp.schemas import NextRequestSchema, NextResponseSchema
from eduid.webapp.idp.sso_session import SSOSession
from eduid.webapp.idp.util import get_login_username

next_views = Blueprint("next", __name__, url_prefix="")


@next_views.route("/next", methods=["POST"])
@UnmarshalWith(NextRequestSchema)
@MarshalWith(NextResponseSchema)
@require_ticket
@uses_sso_session
def next_view(ticket: LoginContext, sso_session: SSOSession | None) -> FluxData:
    """Main state machine for frontend"""
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- Next ({ticket.request_ref}) ---")

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_available)

    _next = login_next_step(ticket, sso_session)
    current_app.logger.debug(f"Login Next: {_next}")

    if _next.message == IdPMsg.unknown_device:
        return success_response(payload={"action": IdPAction.NEW_DEVICE.value})

    if _next.message == IdPMsg.aborted:
        if isinstance(ticket, LoginContextSAML):
            saml_params = cancel_saml_request(ticket, current_app.conf)
            authn_options = _get_authn_options(ticket=ticket, sso_session=sso_session, eppn=None)
            return create_saml_sp_response(saml_params=saml_params, authn_options=authn_options.to_dict())
        elif isinstance(ticket, LoginContextOtherDevice):
            state = ticket.other_device_req
            if state.state in [OtherDeviceState.NEW, OtherDeviceState.IN_PROGRESS, OtherDeviceState.AUTHENTICATED]:
                current_app.logger.info("Aborting login using another device")

                _abort_res = current_app.other_device_db.abort(state)
                if not _abort_res:
                    current_app.logger.warning(f"Login using other device: Failed aborting state {state}")
                    return error_response(message=IdPMsg.general_failure)
                current_app.stats.count("login_using_other_device_abort_device2")

                return success_response(
                    message=IdPMsg.finished,
                    payload={
                        "action": IdPAction.FINISHED.value,
                        "target": url_for("other_device.use_other_2", _external=True),
                    },
                )
            else:
                current_app.logger.info(f"Not aborting use other device in state {state.state}")
        current_app.logger.error(f"Don't know how to abort login request {ticket}")
        return error_response(message=IdPMsg.general_failure)

    # catch assurance problems that we should tell the SP about
    if _next.message == IdPMsg.assurance_failure:
        if isinstance(ticket, LoginContextSAML):
            saml_params = authn_context_class_not_supported(ticket, current_app.conf)
            authn_options = _get_authn_options(ticket=ticket, sso_session=sso_session, eppn=None)
            return create_saml_sp_response(saml_params=saml_params, authn_options=authn_options.to_dict())
        current_app.logger.error(f"Don't know how to send error response for request {ticket}")
        return error_response(message=IdPMsg.general_failure)

    # catch assurance problems that we should tell the USER about
    if _next.message in [
        IdPMsg.identity_proofing_method_not_allowed,
        IdPMsg.mfa_proofing_method_not_allowed,
        IdPMsg.assurance_not_possible,
    ]:
        current_app.logger.error(f"Can not continue with request due to assurance problem: {_next.message}")
        return error_response(message=_next.message)

    required_user = get_required_user(ticket, sso_session)
    if required_user.response:
        return required_user.response
    current_app.logger.debug(f"Required user: {required_user.eppn}")

    if _next.message == IdPMsg.other_device:
        _payload = {
            "action": IdPAction.OTHER_DEVICE.value,
            "target": url_for("other_device.use_other_1", _external=True),
            "authn_options": _get_authn_options(
                ticket=ticket, sso_session=sso_session, eppn=required_user.eppn
            ).to_dict(),
            "service_info": _get_service_info(ticket),
        }

        return success_response(
            message=IdPMsg.must_authenticate,
            payload=_payload,
        )

    if _next.message == IdPMsg.must_authenticate:
        authn_options = _get_authn_options(ticket=ticket, sso_session=sso_session, eppn=required_user.eppn)
        service_info = _get_service_info(ticket)

        if required_user.eppn is None or authn_options.webauthn is False:
            # we don't know the users eppn or the user does not have a security key, show username and password input
            _payload = {
                "action": IdPAction.USERNAMEPWAUTH.value,
                "target": url_for("pw_auth.pw_auth", _external=True),
                "authn_options": authn_options.to_dict(),
                "service_info": service_info,
            }
        else:
            _payload = {
                "action": IdPAction.MFA.value,
                "target": url_for("mfa_auth.mfa_auth", _external=True),
                "authn_options": authn_options.to_dict(),
                "service_info": service_info,
            }

        return success_response(
            message=IdPMsg.must_authenticate,
            payload=_payload,
        )

    if _next.message == IdPMsg.mfa_required:
        authn_options = _get_authn_options(ticket=ticket, sso_session=sso_session, eppn=required_user.eppn)
        service_info = _get_service_info(ticket)

        if _next.authn_state and _next.authn_state.fido_used:
            # we know that the user already provided a single factor security key, offer password as second factor
            # Here we turn off webauthn as an option since we don't want the user to use security key twice
            authn_options.webauthn = False
            _payload = {
                "action": IdPAction.USERNAMEPWAUTH.value,
                "target": url_for("pw_auth.pw_auth", _external=True),
                "authn_options": authn_options.to_dict(),
                "service_info": service_info,
            }
        else:
            _payload = {
                "action": IdPAction.MFA.value,
                "target": url_for("mfa_auth.mfa_auth", _external=True),
                "authn_options": authn_options.to_dict(),
                "service_info": service_info,
            }

        return success_response(
            message=IdPMsg.mfa_required,
            payload=_payload,
        )

    if _next.message == IdPMsg.security_key_required:
        return success_response(
            message=IdPMsg.mfa_required,
            payload={
                "action": IdPAction.MFA.value,
                "target": url_for("mfa_auth.mfa_auth", _external=True),
                "authn_options": _get_authn_options(
                    ticket=ticket, sso_session=sso_session, eppn=required_user.eppn
                ).to_dict(),
            },
        )

    if _next.message == IdPMsg.tou_required:
        return success_response(
            message=IdPMsg.tou_required,
            payload={
                "action": IdPAction.TOU.value,
                "target": url_for("tou.tou", _external=True),
                "authn_options": _get_authn_options(
                    ticket=ticket, sso_session=sso_session, eppn=required_user.eppn
                ).to_dict(),
            },
        )

    if _next.message == IdPMsg.user_terminated:
        return error_response(message=IdPMsg.user_terminated)

    if _next.message == IdPMsg.proceed:
        if not sso_session:
            return error_response(message=IdPMsg.no_sso_session)

        user = lookup_user(sso_session.eppn, managed_account_allowed=True)
        if not user:
            current_app.logger.error(f"User with eppn {sso_session.eppn} (from SSO session) not found")
            return error_response(message=IdPMsg.general_failure)

        sso = SSO(sso_session=sso_session)
        # please mypy
        if not _next.authn_info or not _next.authn_state:
            raise RuntimeError(f"Missing expected data in next result: {_next}")

        try:
            # Logging stats is optional, make sure we never fail a login because of it
            _log_user_agent()
        except Exception:
            current_app.logger.exception("Producing User-Agent stats failed")

        if current_app.conf.known_devices_feature_enabled:
            if ticket.known_device and ticket.known_device_info:
                if ticket.known_device.data.login_counter is None:
                    ticket.known_device.data.login_counter = 0  # for mypy
                ticket.known_device.data.login_counter += 1
                current_app.stats.gauge("login_known_device_login_counter", ticket.known_device.data.login_counter)
                _update_known_device_data(ticket, user, _next.authn_info)
                current_app.known_device_db.save(
                    ticket.known_device, from_browser=ticket.known_device_info, ttl=current_app.conf.known_devices_ttl
                )

        if current_app.conf.geo_statistics_feature_enabled:
            try:
                # Logging stats is optional, make sure we never fail a login because of it
                _geo_statistics(ticket=ticket, sso_session=sso_session)
            except Exception:
                current_app.logger.exception("Producing Geo stats failed")

        if isinstance(ticket, LoginContextSAML):
            saml_params = sso.get_response_params(_next.authn_info, ticket, user)
            authn_options = _get_authn_options(ticket=ticket, sso_session=sso_session, eppn=required_user.eppn)
            return create_saml_sp_response(saml_params=saml_params, authn_options=authn_options.to_dict())
        elif isinstance(ticket, LoginContextOtherDevice):
            if not ticket.is_other_device_2:
                # We shouldn't be able to get here, but this clearly shows where this code runs
                current_app.logger.warning("Ticket is LoginContextOtherDevice, but this is not device #2")
                return error_response(message=IdPMsg.general_failure)

            return device2_finish(ticket, sso_session, _next.authn_state)
        current_app.logger.error(f"Don't know how to finish login request {ticket}")
        return error_response(message=IdPMsg.general_failure)

    current_app.logger.error(f"Do not know how to log in the user. Fell through with next: {_next}")
    return error_response(message=IdPMsg.not_implemented)


@dataclass
class AuthnOptions:
    """
    Different options regarding authentication. These might change during the course of the authentication.

    For example: after providing a username, password authentication becomes available if the user has such
    credentials.
    """

    # Is this a re-authentication request? Meaning the very same user _has_ to log in, can't switch to another user.
    is_reauthn: bool
    # What to use in the greeting of the user at the login page
    display_name: str | None = None
    # Is this login locked to being performed by a particular user? (Identified by the email/phone/...)
    forced_username: str | None = None
    # Can an unknown user log in using just a swedish eID? Yes, if there is an eduID user with the users (verified) NIN.
    swedish_eid: bool = True
    # If the user has a session, 'logout' should be shown (to allow switch of users).
    has_session: bool = False
    # Can the user log (an unknown user) log in using another device? Sure.
    other_device: bool = True
    # Can the frontend start with just asking for a password? No, not unless we know who the user is.
    password: bool = False
    # Can an unknown user log in using a username and a password? Defaults to True.
    usernamepassword: bool = True
    # Can the frontend start with just asking for a username? Sure.
    username: bool = True
    # Can an unknown user log in using a webauthn credential? Yes.
    webauthn: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def valid_options(self) -> list[str]:
        _data = self.to_dict()
        return [x for x in _data if _data[x]]


def _get_authn_options(ticket: LoginContext, sso_session: SSOSession | None, eppn: str | None) -> AuthnOptions:
    res = AuthnOptions(is_reauthn=ticket.reauthn_required)

    # Availability of "login using another device" is controlled by configuration for now.
    res.other_device = current_app.conf.allow_other_device_logins

    if ticket.is_other_device_2:
        current_app.logger.debug("This is already a request to log in to another device, not allowing other_device")
        res.other_device = False

    if eppn:
        _set_user_options(res, eppn)

    if sso_session:
        # Since the user has a session, logout should be shown (to allow change of user)
        res.has_session = True

    current_app.logger.debug(f"Valid authn options at this time: {res.valid_options}")

    return res


@dataclass
class RequiredUserResult:
    response: FluxData | None = None
    eppn: str | None = None


def get_required_user(ticket: LoginContext, sso_session: SSOSession | None) -> RequiredUserResult:
    """
    Figure out if something dictates a user that _must_ be used to log in at this time.

    The requirement can come from quite a few places, so try to check it using a uniform and extendable method.
    """
    eppn_set: set[str] = set()

    if isinstance(ticket, LoginContextSAML) and ticket.service_requested_eppn:
        _eppn = ticket.service_requested_eppn
        current_app.logger.debug(f"SP requests login as {_eppn}")
        eppn_set.add(_eppn)

    if isinstance(ticket, LoginContextOtherDevice) and ticket.is_other_device_2 and ticket.service_requested_eppn:
        _eppn = ticket.service_requested_eppn
        current_app.logger.debug(f"Other device requests login as {_eppn}")
        eppn_set.add(_eppn)

    if ticket.known_device and ticket.known_device.data.eppn:
        _eppn = ticket.known_device.data.eppn
        current_app.logger.debug(f"Device belongs to {_eppn}")
        eppn_set.add(_eppn)

    if sso_session and sso_session.eppn:
        _eppn = sso_session.eppn
        current_app.logger.debug(f"SSO session belongs to {_eppn}")
        eppn_set.add(_eppn)

    if len(eppn_set) > 1:
        current_app.logger.warning(f"Contradicting information about who needs to log in: {eppn_set}")
        return RequiredUserResult(response=error_response(message=IdPMsg.wrong_user))

    if eppn_set:
        current_app.logger.info(f"Determined user to log in to be {eppn_set}")
        return RequiredUserResult(eppn=eppn_set.pop())

    return RequiredUserResult(eppn=None)


def _get_service_info(ticket: LoginContext) -> dict[str, Any]:
    try:
        if ticket.service_info is not None:
            return ticket.service_info.to_dict()
    except Exception:
        current_app.logger.exception("Failed getting service info for SP")
    return {}


def _set_user_options(res: AuthnOptions, eppn: str) -> None:
    """Augment the AuthnOptions instance with information about the current user"""
    user = lookup_user(eppn, managed_account_allowed=True)
    if user:
        current_app.logger.debug(
            f"User logging in (from either known device, other device, SSO session, or SP request): {user}"
        )
        if user.credentials.filter(Password):
            current_app.logger.debug("User has a Password credential")
            res.password = True

        if not user.credentials.filter(FidoCredential):
            current_app.logger.debug("User does NOT have a FIDO/Webauthn credential")
            res.webauthn = False

        if user.locked_identity.nin:
            current_app.logger.debug("User has a locked NIN -> swedish eID is possible")
            res.swedish_eid = True
        else:
            current_app.logger.debug("No locked NIN for user -> swedish eID NOT possible")
            res.swedish_eid = False

        res.forced_username = get_login_username(user)
        current_app.logger.debug(f"User forced_username: {res.forced_username}")

        # TODO: Should ideally distinguish between a _real_ forced username, such as the SP requiring a
        #       specific user to log in, and e.g. a known device where the user might choose to reset
        #       the known device, and thus avoid the requirement.
        if res.forced_username:
            res.username = False

        res.display_name = user.friendly_identifier or res.forced_username


def _geo_statistics(ticket: LoginContext, sso_session: SSOSession | None) -> None:
    """Log user statistics from login event"""

    if not sso_session:
        return None

    if not current_app.conf.geo_statistics_secret_key or not current_app.conf.geo_statistics_url:
        return None

    ua = get_user_agent()
    if not ua:
        return None

    if ua.parsed.browser.family in ["Python Requests", "PingdomBot"] or ua.parsed.is_bot:
        return None

    secret = urlsafe_b64decode(bytes(current_app.conf.geo_statistics_secret_key, "ascii"))

    user_hash = hmac.HMAC(secret, hashes.SHA256())
    user_hash.update(bytes(sso_session.eppn, "utf-8"))

    d: dict[str, Any] = {
        "data": {
            "user_id": user_hash.finalize().hex(),
            "client_ip": request.remote_addr,
            "known_device": bool(ticket.known_device),
            "user_agent": {"browser": {}, "os": {}, "device": {}, "sophisticated": {}},
        }
    }

    data = d["data"]
    data["user_agent"]["browser"]["family"] = ua.parsed.browser.family
    data["user_agent"]["os"]["family"] = ua.parsed.os.family
    data["user_agent"]["device"]["family"] = ua.parsed.device.family
    data["user_agent"]["sophisticated"]["is_mobile"] = ua.parsed.is_mobile
    data["user_agent"]["sophisticated"]["is_pc"] = ua.parsed.is_pc
    data["user_agent"]["sophisticated"]["is_tablet"] = ua.parsed.is_tablet
    data["user_agent"]["sophisticated"]["is_touch_capable"] = ua.parsed.is_touch_capable

    try:
        resp = requests.post(current_app.conf.geo_statistics_url, json=d, timeout=1)
        current_app.logger.debug(f"response from geo-statistics app: {resp.json}")
    except requests.RequestException:
        current_app.logger.exception("Failed to contact geo-statistics app")


def _log_user_agent() -> None:
    """Log some statistics from the User-Agent header"""
    ua = get_user_agent()

    if ua:
        current_app.logger.debug(f"Logging in user with User-Agent {repr(ua.safe_str)}")

    if not ua:
        current_app.stats.count("login_finished_ua_is_none")
        return

    if ua.parsed.browser.family in ["Python Requests", "PingdomBot"]:
        # Don't want to log further details about the monitoring of the IdPs and apps
        current_app.stats.count("login_finished_ua_is_monitoring")
        return

    if ua.parsed.is_bot:
        # Don't want bots to affect e.g. OS count
        current_app.stats.count("login_finished_ua_is_bot")
        return

    # log a 'total count' of users to avoid having to sum up potential unknowns, such as browser families
    current_app.stats.count("login_finished_ua_is_user")

    if ua.parsed.is_mobile:
        current_app.stats.count("login_finished_ua_is_mobile")
    elif ua.parsed.is_pc:
        current_app.stats.count("login_finished_ua_is_pc")
    elif ua.parsed.is_tablet:
        current_app.stats.count("login_finished_ua_is_tablet")
    else:
        current_app.stats.count("login_finished_ua_is_unknown")
        return

    def _safe_stat(prefix: str, value: str) -> None:
        safe_value = re.sub("[^a-zA-Z0-9.]", "_", value[:20])
        current_app.stats.count(f"{prefix}_{safe_value}")

    _safe_stat("login_finished_ua_device", ua.parsed.device.family)
    _safe_stat("login_finished_ua_os_family", ua.parsed.os.family)
    _safe_stat("login_finished_ua_browser", ua.parsed.browser.family)

    return None


def _update_known_device_data(ticket: LoginContext, user: IdPUser, authn_info: AuthnInfo) -> None:
    """
    Update things we know about this device:
      - whom it belongs to (eppn)
      - current User-Agent
      - current IP address
      - time of last login

    For privacy reasons, this data is stored encrypted in the database and the encryption key
    is only given to the device. This means we can't access it again until the device returns
    and provides the ticket.known_device_info.shared (encryption key and state id) to us again.
    """
    if not ticket.known_device:
        # please mypy
        return

    if not ticket.known_device.data.eppn:
        current_app.logger.debug("Known device: Recording new eppn")
        ticket.known_device.data.eppn = user.eppn
        current_app.stats.count("login_new_device_first_login_finished")
    elif ticket.known_device.data.eppn != user.eppn:
        # We quite possibly want to block this in production, after verifying it "shouldn't happen"
        current_app.logger.warning(f"Known device: eppn changed from {ticket.known_device.data.eppn} to {user.eppn}")
        ticket.known_device.data.eppn = user.eppn
        current_app.stats.count("login_known_device_changed_eppn")
    else:
        current_app.logger.debug("Known device: Same user logging in")
        current_app.stats.count("login_known_device_login_finished")

    if ticket.known_device.data.ip_address != request.remote_addr:
        if ticket.known_device.data.ip_address:
            current_app.stats.count("login_known_device_ip_changed")
        current_app.logger.debug("Known device: Recording new IP address")
        current_app.logger.debug(f"Known device:   old {ticket.known_device.data.ip_address}")
        current_app.logger.debug(f"Known device:   new {request.remote_addr}")
        ticket.known_device.data.ip_address = request.remote_addr

    _ua = get_user_agent()
    _ua_str = None
    if _ua:
        _ua_str = str(_ua.parsed)
    if ticket.known_device.data.user_agent != _ua_str:
        if ticket.known_device.data.user_agent:
            current_app.stats.count("login_known_device_ua_changed")
        current_app.logger.debug("Known device: Recording new User-Agent")
        current_app.logger.debug(f"Known device:   old {ticket.known_device.data.user_agent}")
        current_app.logger.debug(f"Known device:   new {_ua_str}")
        ticket.known_device.data.user_agent = _ua_str

    if ticket.known_device.data.last_login:
        age = authn_info.instant - ticket.known_device.data.last_login
        current_app.logger.debug(f"Known device: Last login from this device was {age} before this one")
        current_app.logger.debug(f"Known device:   old {ticket.known_device.data.last_login.isoformat()}")
        current_app.logger.debug(f"Known device:   new {authn_info.instant.isoformat()}")
    ticket.known_device.data.last_login = authn_info.instant
