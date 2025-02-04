from __future__ import annotations

import logging
from abc import ABC
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime
from enum import StrEnum, unique
from typing import Any, NewType, TypeVar, cast
from uuid import uuid4

from fido2.webauthn import AuthenticatorAttachment
from pydantic import BaseModel, Field, ValidationError, field_validator
from pydantic_core.core_schema import ValidationInfo

from eduid.common.config.base import FrontendAction
from eduid.common.misc.timeutil import utc_now
from eduid.common.utils import uuid4_str
from eduid.userdb.credentials import Credential
from eduid.userdb.credentials.external import TrustFramework
from eduid.userdb.element import ElementKey
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction, BankIDAcsAction, EidasAcsAction
from eduid.webapp.freja_eid.callback_enums import FrejaEIDAction
from eduid.webapp.idp.other_device.data import OtherDeviceId
from eduid.webapp.svipe_id.callback_enums import SvipeIDAction

__author__ = "ft"


logger = logging.getLogger(__name__)


AuthnRequestRef = NewType("AuthnRequestRef", str)
OIDCState = NewType("OIDCState", str)


class SessionNSBase(BaseModel, ABC):
    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls: type[TSessionNSSubclass], data: Mapping[str, Any]) -> TSessionNSSubclass:
        _data = cls._from_dict_transform(data)

        try:
            return cls(**_data)
        except ValidationError:
            logger.warning(f"Could not parse session namespace:\n{_data}")
            raise

    @classmethod
    def _from_dict_transform(cls: type[SessionNSBase], data: Mapping[str, Any]) -> dict[str, Any]:
        _data = deepcopy(data)  # do not modify callers data
        return dict(_data)

    def clear(self) -> None:
        """
        Clears all session namespace data.
        """
        self.__dict__ = self.model_construct(_cls=self.__class__, field_set={}).__dict__


TSessionNSSubclass = TypeVar("TSessionNSSubclass", bound=SessionNSBase)


@unique
class LoginApplication(StrEnum):
    idp = "idp"
    authn = "authn"
    signup = "signup"


class Common(SessionNSBase):
    eppn: str | None = None
    is_logged_in: bool = False
    login_source: LoginApplication | None = None
    preferred_language: str | None = None


class Captcha(SessionNSBase):
    completed: bool = False
    internal_answer: str | None = None
    bad_attempts: int = 0


WebauthnState = NewType("WebauthnState", dict[str, Any])


class MfaAction(SessionNSBase):
    success: bool = False
    login_ref: str | None = None
    authn_req_ref: AuthnRequestRef | None = None
    credential_used: ElementKey | None = None
    # Third-party MFA parameters
    framework: TrustFramework | None = None
    required_loa: list[str] = Field(default_factory=list)
    issuer: str | None = None
    authn_instant: str | None = None
    authn_context: str | None = None
    # Webauthn MFA parameters
    webauthn_state: WebauthnState | None = None


class TimestampedNS(SessionNSBase):
    # This timestamp is updated automatically when the data in the namespace changes.
    # Today, the timestamp is used to signal "freshness" of an action requested in
    # actions by the idp, or in authn by signup. This seems like a bad idea and should
    # be improved, and this 'ts' field should probably only be seen as a troubleshooting
    # tool, to help find relevant entries in logfiles etc.
    ts: datetime = Field(default_factory=utc_now)


class ResetPasswordNS(SessionNSBase):
    generated_password_hash: str | None = None
    # XXX the keys below are not in use yet. They are set in eduid.webapp.common,
    # in a way that the security app understands. Once the (reset|change)
    # password views are removed from the security app, we will be able to
    # start using them. The session key reauthn-for-chpass is in the same
    # situation.
    extrasec_u2f_challenge: str | None = None
    extrasec_webauthn_state: str | None = None
    captcha: Captcha = Field(default_factory=Captcha)


class WebauthnRegistration(SessionNSBase):
    # Data stored between webauthn register "begin" and "complete"
    webauthn_state: WebauthnState
    authenticator: AuthenticatorAttachment


class SecurityNS(SessionNSBase):
    # used for new change_password
    generated_password_hash: str | None = None
    # used for update user data from official source
    user_requested_update: datetime | None = None
    webauthn_registration: WebauthnRegistration | None = None


class Name(SessionNSBase):
    given_name: str | None = None
    surname: str | None = None


class EmailVerification(SessionNSBase):
    completed: bool = False
    address: str | None = None
    verification_code: str | None = None
    bad_attempts: int = 0
    sent_at: datetime | None = None
    reference: str | None = None


class Invite(SessionNSBase):
    completed: bool = False
    initiated_signup: bool = False
    invite_code: str | None = None
    finish_url: str | None = None


class Tou(SessionNSBase):
    completed: bool = False
    version: str | None = None


class Credentials(SessionNSBase):
    completed: bool = False
    generated_password: str | None = None
    webauthn: Any | None = None  # TODO: implement webauthn signup


class Signup(TimestampedNS):
    user_created: bool = False
    user_created_at: datetime | None = None
    name: Name = Field(default_factory=Name)
    email: EmailVerification = Field(default_factory=EmailVerification)
    invite: Invite = Field(default_factory=Invite)
    tou: Tou = Field(default_factory=Tou)
    captcha: Captcha = Field(default_factory=Captcha)
    credentials: Credentials = Field(default_factory=Credentials)


class Phone(SessionNSBase):
    captcha: Captcha = Field(default_factory=Captcha)


RequestRef = NewType("RequestRef", str)


class OnetimeCredType(StrEnum):
    external_mfa = "ext_mfa"


class OnetimeCredential(Credential):
    credential_id: str = Field(default_factory=lambda: str(uuid4()))
    type: OnetimeCredType

    # External MFA auth parameters
    issuer: str
    authn_context: str
    timestamp: datetime

    @property
    def key(self) -> ElementKey:
        return ElementKey(self.credential_id)


class IdP_PendingRequest(BaseModel, ABC):
    aborted: bool | None = False
    used: bool | None = False  # set to True after the request has been completed (to handle 'back' button presses)
    template_show_msg: str | None = None  # set when the template version of the idp should show a message to the user
    # Credentials used while authenticating _this SAML request_. Not ones inherited from SSO.
    credentials_used: dict[ElementKey, datetime] = Field(default_factory=dict)
    onetime_credentials: dict[ElementKey, OnetimeCredential] = Field(default_factory=dict)


class IdP_SAMLPendingRequest(IdP_PendingRequest):
    request: str
    binding: str
    relay_state: str | None = None
    # a pointer to an ongoing request to login using another device
    other_device_state_id: OtherDeviceId | None = None


class IdP_OtherDevicePendingRequest(IdP_PendingRequest):
    state_id: OtherDeviceId | None = None  # can be None on aborted/expired requests


IdP_PendingRequestSubclass = IdP_SAMLPendingRequest | IdP_OtherDevicePendingRequest


class IdP_Namespace(TimestampedNS):
    # The SSO cookie value last set by the IdP. Used to debug issues with browsers not
    # honoring Set-Cookie in redirects, or something.
    sso_cookie_val: str | None = None
    pending_requests: dict[RequestRef, IdP_PendingRequestSubclass] = Field(default={})

    def log_credential_used(
        self, request_ref: RequestRef, credential: Credential | OnetimeCredential, timestamp: datetime
    ) -> None:
        """Log the credential used in the session, under this particular SAML request"""
        if isinstance(credential, OnetimeCredential):
            self.pending_requests[request_ref].onetime_credentials[credential.key] = credential
        self.pending_requests[request_ref].credentials_used[credential.key] = timestamp


class BaseAuthnRequest(BaseModel, ABC):
    frontend_action: FrontendAction  # what action frontend is performing
    frontend_state: str | None = None  # opaque data from frontend, returned in /status
    method: str | None = None  # proofing method that frontend is invoking
    post_authn_action: AuthnAcsAction | EidasAcsAction | SvipeIDAction | BankIDAcsAction | FrejaEIDAction | None = None
    # proofing_credential_id is the credential being person-proofed, when doing that
    proofing_credential_id: ElementKey | None = None
    created_ts: datetime = Field(default_factory=utc_now)
    authn_instant: datetime | None = None
    status: str | None = None  # populated by the SAML2 ACS/OIDC callback action
    error: bool | None = None
    finish_url: str  # the URL to redirect to after authentication is complete
    consumed: bool = False  # an operation that requires a new authentication has used this one already


class SP_AuthnRequest(BaseAuthnRequest):
    authn_id: AuthnRequestRef = Field(default_factory=lambda: AuthnRequestRef(uuid4_str()))
    credentials_used: list[ElementKey] = Field(default_factory=list)
    req_authn_ctx: list[str] = Field(
        default_factory=list
    )  # the authentication contexts requested for this authentication
    asserted_authn_ctx: str | None = None  # the authentication contexts asserted for this authentication

    def formatted_finish_url(self, app_name: str) -> str:
        return self.finish_url.format(app_name=app_name, authn_id=self.authn_id)


PySAML2Dicts = NewType("PySAML2Dicts", dict[str, dict[str, Any]])


class SPAuthnData(BaseModel):
    pysaml2_dicts: PySAML2Dicts = Field(default=cast(PySAML2Dicts, dict()))
    authns: dict[AuthnRequestRef, SP_AuthnRequest] = Field(default_factory=dict)

    @field_validator("authns", mode="after")
    @classmethod
    def authns_cleanup(
        cls, v: dict[AuthnRequestRef, SP_AuthnRequest], info: ValidationInfo
    ) -> dict[AuthnRequestRef, SP_AuthnRequest]:
        """
        Keep the authns list from growing indefinitely.
        """
        # if authns is larger than 10, sort on created_ts and remove the oldest
        if len(v) > 10:
            items = sorted(v.items(), reverse=True, key=lambda item: item[1].created_ts)
            return dict(items[:10])
        return v

    def get_authn_for_frontend_action(self, action: FrontendAction) -> SP_AuthnRequest | None:
        # sort authn actions by created_ts and return the first one (latest) that matches the action
        for authn in sorted(self.authns.values(), reverse=True, key=lambda item: item.created_ts):
            if authn.frontend_action == action:
                return authn
        return None


class EidasNamespace(SessionNSBase):
    sp: SPAuthnData = Field(default=SPAuthnData())


class AuthnNamespace(SessionNSBase):
    sp: SPAuthnData = Field(default=SPAuthnData())
    name_id: str | None = None  # SAML NameID, used in logout
    next: str | None = None


class RP_AuthnRequest(BaseAuthnRequest):
    authn_id: OIDCState

    def formatted_finish_url(self, app_name: str) -> str:
        return self.finish_url.format(app_name=app_name, authn_id=self.authn_id)


class RPAuthnData(BaseModel):
    authlib_cache: dict[str, Any] = Field(default_factory=dict)
    authns: dict[OIDCState, RP_AuthnRequest] = Field(default_factory=dict)


class SvipeIDNamespace(SessionNSBase):
    rp: RPAuthnData = Field(default=RPAuthnData())


class BankIDNamespace(SessionNSBase):
    sp: SPAuthnData = Field(default=SPAuthnData())


class FrejaEIDNamespace(SessionNSBase):
    rp: RPAuthnData = Field(default=RPAuthnData())
