import logging
from abc import ABC
from collections.abc import Sequence
from typing import Optional
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict

from eduid.common.models.saml2 import EduidAuthnContextClass
from eduid.webapp.common.session.namespaces import (
    IdP_OtherDevicePendingRequest,
    IdP_PendingRequest,
    IdP_SAMLPendingRequest,
    RequestRef,
)
from eduid.webapp.idp.idp_saml import IdP_SAMLRequest, ServiceInfo
from eduid.webapp.idp.known_device import BrowserDeviceInfo, KnownDevice
from eduid.webapp.idp.other_device.data import OtherDeviceId
from eduid.webapp.idp.other_device.db import OtherDevice

logger = logging.getLogger(__name__)


class LoginContext(ABC, BaseModel):
    """
    Class to hold data about an ongoing login process in memory only.

    Instances of this class is used more or less like a context being passed around.
    None of this data is persisted anywhere.

    This is more or less an interface to the current 'pending_request' in the session,
    identified by the request_ref.
    """

    request_ref: RequestRef
    known_device_info: BrowserDeviceInfo | None = None
    remember_me: bool | None = None  # if the user wants to be remembered or not (on this device)
    _known_device: KnownDevice | None = None
    _pending_request: IdP_PendingRequest | None = None
    model_config = ConfigDict()

    def __str__(self) -> str:
        return f"<{self.__class__.__name__}: key={self.request_ref}>"

    @property
    def pending_request(self) -> IdP_PendingRequest:
        if self._pending_request is None:
            from eduid.webapp.common.session import session

            pending_request = session.idp.pending_requests.get(self.request_ref)
            if not pending_request:
                raise RuntimeError(f"No pending request with ref {self.request_ref} found in session")
            self._pending_request = pending_request

        return self._pending_request

    @property
    def request_id(self) -> str | None:
        raise NotImplementedError("Subclass must implement request_id")

    @property
    def authn_contexts(self) -> list[str]:
        raise NotImplementedError("Subclass must implement authn_contexts")

    @property
    def reauthn_required(self) -> bool:
        raise NotImplementedError("Subclass must implement reauthn_required")

    @property
    def service_requested_eppn(self) -> str | None:
        """The eppn of the user the service (e.g. SAML SP) requests logs in"""
        raise NotImplementedError("Subclass must implement service_requested_eppn")

    @property
    def service_info(self) -> ServiceInfo | None:
        """Information about the service where the user is logging in"""
        raise NotImplementedError("Subclass must implement service_requested_eppn")

    @property
    def other_device_state_id(self) -> OtherDeviceId | None:
        """Get the state_id for the OtherDevice state, if the user wants to log in using another device."""
        raise NotImplementedError("Subclass must implement other_device_state_id")

    @property
    def is_other_device_1(self) -> bool:
        """Check if this is a request to log in on another device (specifically device #1)."""
        raise NotImplementedError("Subclass must implement is_other_device_1")

    @property
    def is_other_device_2(self) -> bool:
        """Check if this is a request to log in on another device (specifically device #2)."""
        raise NotImplementedError("Subclass must implement is_other_device_2")

    def set_other_device_state(self, state_id: OtherDeviceId | None) -> None:
        if isinstance(self.pending_request, IdP_SAMLPendingRequest):
            self.pending_request.other_device_state_id = state_id
        elif isinstance(self.pending_request, IdP_OtherDevicePendingRequest):
            self.pending_request.state_id = None
        else:
            raise TypeError(f"Can't set other_device on pending request of type {type(self.pending_request)}")

    def get_requested_authn_context(self) -> list[EduidAuthnContextClass]:
        raise NotImplementedError("Subclass must implement get_requested_authn_context")

    @property
    def known_device(self) -> KnownDevice | None:
        if not self._known_device:
            if self.known_device_info:
                from eduid.webapp.idp.app import current_idp_app as current_app

                self._known_device = current_app.known_device_db.get_state_by_browser_info(self.known_device_info)
        return self._known_device

    def forget_known_device(self) -> None:
        """User has requested to not be remembered on this device"""
        self._known_device = None
        self.known_device_info = None


class LoginContextSAML(LoginContext):
    _saml_req: Optional["IdP_SAMLRequest"] = None

    @property
    def SAMLRequest(self) -> str:
        pending = self.pending_request
        if not isinstance(pending, IdP_SAMLPendingRequest):
            raise ValueError("Pending request not initialised (or not a SAML request)")
        if not isinstance(pending.request, str):
            raise ValueError("pending_request.request not initialised")
        return pending.request

    @property
    def RelayState(self) -> str:
        pending = self.pending_request
        if not isinstance(pending, IdP_SAMLPendingRequest):
            raise ValueError("Pending request not initialised (or not a SAML request)")
        return pending.relay_state or ""

    @property
    def binding(self) -> str:
        pending = self.pending_request
        if not isinstance(pending, IdP_SAMLPendingRequest):
            raise ValueError("Pending request not initialised (or not a SAML request)")
        if not isinstance(pending.binding, str):
            raise ValueError("pending_request.binding not initialised")
        return pending.binding

    @property
    def query_string(self) -> str:
        qs = {"SAMLRequest": self.SAMLRequest, "RelayState": self.RelayState}
        return urlencode(qs)

    @property
    def saml_req(self) -> IdP_SAMLRequest:
        if self._saml_req is None:
            # avoid circular import
            from eduid.webapp.idp.app import current_idp_app as current_app
            from eduid.webapp.idp.idp_saml import IdP_SAMLRequest

            self._saml_req = IdP_SAMLRequest(
                self.SAMLRequest, self.binding, current_app.IDP, debug=current_app.conf.debug
            )
        return self._saml_req

    @property
    def request_id(self) -> str | None:
        return self.saml_req.request_id

    @property
    def authn_contexts(self) -> list[str]:
        return self.saml_req.get_requested_authn_contexts()

    @property
    def reauthn_required(self) -> bool:
        return self.saml_req.force_authn

    @property
    def service_requested_eppn(self) -> str | None:
        res = None
        _login_subject = self.saml_req.login_subject
        if _login_subject is not None:
            # avoid circular import
            from eduid.webapp.idp.app import current_idp_app as current_app

            logger.debug(f"Login subject: {_login_subject}")

            if self.saml_req.sp_entity_id not in current_app.conf.request_subject_allowed_entity_ids:
                logger.info(f"SP {self.saml_req.sp_entity_id} not allowed to request login subject")
                return None

            res = _login_subject

            # Login subject might be set by the idpproxy when requesting the user to do MFA step up
            if res.endswith(current_app.conf.default_eppn_scope):
                # remove the @scope
                res = res[: -(len(current_app.conf.default_eppn_scope) + 1)]
        return res

    @property
    def service_info(self) -> ServiceInfo | None:
        """Information about the service where the user is logging in"""
        _info = self.saml_req.service_info
        if not _info:
            return None
        return ServiceInfo(display_name=_info.get("display_name", {}))

    @property
    def other_device_state_id(self) -> OtherDeviceId | None:
        # On device #1, the pending_request has a pointer to the other-device-state
        # Use temporary variable to avoid pycharm warning
        #   Unresolved attribute reference 'other_device_state_id' for class 'IdP_PendingRequest'
        _pending = self.pending_request
        if isinstance(_pending, IdP_SAMLPendingRequest):
            return _pending.other_device_state_id
        return None

    @property
    def is_other_device_1(self) -> bool:
        """Check if this is a request to log in on another device (specifically device #1).

        If so, since this is an instance of IdP_SAMLPendingRequest (checked in self.other_device_state_id)
        this is a request being processed on the FIRST device. This is the INITIATING device, where the user
        arrived at the Login app with a SAML authentication request, and chose to log in using another device.
        """
        return self.other_device_state_id is not None

    @property
    def is_other_device_2(self) -> bool:
        """Check if this is a request to log in on another device (specifically device #2)."""
        return False

    def get_requested_authn_context(self) -> list[EduidAuthnContextClass]:
        """
        Return the authn context (if any) that was originally requested.

        """
        return _pick_authn_context(self.authn_contexts, self.request_ref)


class LoginContextOtherDevice(LoginContext):
    other_device_req: OtherDevice

    @property
    def request_id(self) -> str | None:
        return self.other_device_req.device1.request_id

    @property
    def authn_contexts(self) -> list[str]:
        if self.other_device_req.device1.authn_context is None:
            return []
        return [item.value for item in self.other_device_req.device1.authn_context]

    @property
    def reauthn_required(self) -> bool:
        return self.other_device_req.device1.reauthn_required

    @property
    def other_device_state_id(self) -> OtherDeviceId | None:
        # On device #2, the pending request is the other-device-state
        _pending = self.pending_request
        if isinstance(_pending, IdP_OtherDevicePendingRequest):
            return _pending.state_id
        return None

    @property
    def is_other_device_1(self) -> bool:
        """Check if this is a request to log in on another device (specifically device #1)."""
        return False

    @property
    def is_other_device_2(self) -> bool:
        """Check if this is a request to log in on another device (specifically device #2).

        If so, since this is an instance of IdP_OtherDevicePendingRequest (checked in self.other_device_state_id)
        this is a request being processed on the SECOND device. This is the AUTHENTICATING device, where the user
        has used a camera to scan the QR code shown on the OTHER device (first, initiating)."""
        return self.other_device_state_id is not None

    def get_requested_authn_context(self) -> list[EduidAuthnContextClass]:
        """
        Return the authn context (if any) that was originally requested on the first device.

        """
        return _pick_authn_context(self.authn_contexts, self.request_ref)

    @property
    def service_requested_eppn(self) -> str | None:
        return self.other_device_req.eppn

    @property
    def service_info(self) -> ServiceInfo | None:
        """Information about the service where the user is logging in"""
        return None


def _pick_authn_context(accrs: Sequence[str], log_tag: str) -> list[EduidAuthnContextClass]:
    if not accrs:
        logger.info(f"{log_tag}: No authnContextClassRef, using {EduidAuthnContextClass.NONE}")
        return [EduidAuthnContextClass.NONE]
    known = []
    for x in accrs:
        if x in EduidAuthnContextClass:
            known += [EduidAuthnContextClass(x)]
        else:
            logger.info(f"{log_tag}: Unknown authnContextClassRef: {x}")
            if EduidAuthnContextClass.NOT_IMPLEMENTED not in known:
                # only add one not implemented error to the list
                known += [EduidAuthnContextClass.NOT_IMPLEMENTED]
    return known
