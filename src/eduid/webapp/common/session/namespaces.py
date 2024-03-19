from __future__ import annotations

import logging
from abc import ABC
from copy import deepcopy
from datetime import datetime
from enum import Enum, unique
from typing import Any, List, Mapping, NewType, Optional, TypeVar, Union, cast
from uuid import uuid4

from fido2.webauthn import AuthenticatorAttachment
from pydantic import BaseModel, Field, ValidationError

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials import Credential
from eduid.userdb.credentials.external import TrustFramework
from eduid.userdb.element import ElementKey
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction, BankIDAcsAction, EidasAcsAction
from eduid.webapp.idp.other_device.data import OtherDeviceId
from eduid.webapp.svipe_id.callback_enums import SvipeIDAction

__author__ = "ft"


logger = logging.getLogger(__name__)


AuthnRequestRef = NewType("AuthnRequestRef", str)
OIDCState = NewType("OIDCState", str)


class SessionNSBase(BaseModel, ABC):
    def to_dict(self) -> dict[str, Any]:
        return self.dict()

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


TSessionNSSubclass = TypeVar("TSessionNSSubclass", bound=SessionNSBase)


@unique
class LoginApplication(str, Enum):
    idp = "idp"
    authn = "authn"
    signup = "signup"


@unique
class MfaActionError(str, Enum):
    authn_context_mismatch = "authn_context_mismatch"
    authn_too_old = "authn_too_old"
    nin_not_matching = "nin_not_matching"
    foreign_eid_not_matching = "foreign_eid_not_matching"


class Common(SessionNSBase):
    eppn: Optional[str] = None
    is_logged_in: bool = False
    login_source: Optional[LoginApplication] = None
    preferred_language: Optional[str] = None


WebauthnState = NewType("WebauthnState", dict[str, Any])


class MfaAction(SessionNSBase):
    success: bool = False
    error: Optional[MfaActionError] = None
    login_ref: Optional[str] = None
    authn_req_ref: Optional[AuthnRequestRef] = None
    credential_used: Optional[ElementKey] = None
    # Third-party MFA parameters
    framework: Optional[TrustFramework] = None
    required_loa: list[str] = Field(default_factory=list)
    issuer: Optional[str] = None
    authn_instant: Optional[str] = None
    authn_context: Optional[str] = None
    # Webauthn MFA parameters
    webauthn_state: Optional[WebauthnState] = None


class TimestampedNS(SessionNSBase):
    # This timestamp is updated automatically when the data in the namespace changes.
    # Today, the timestamp is used to signal "freshness" of an action requested in
    # actions by the idp, or in authn by signup. This seems like a bad idea and should
    # be improved, and this 'ts' field should probably only be seen as a troubleshooting
    # tool, to help find relevant entries in logfiles etc.
    ts: datetime = Field(default_factory=utc_now)


class ResetPasswordNS(SessionNSBase):
    generated_password_hash: Optional[str] = None
    # XXX the keys below are not in use yet. They are set in eduid.webapp.common,
    # in a way that the security app understands. Once the (reset|change)
    # password views are removed from the security app, we will be able to
    # start using them. The session key reauthn-for-chpass is in the same
    # situation.
    extrasec_u2f_challenge: Optional[str] = None
    extrasec_webauthn_state: Optional[str] = None


class WebauthnRegistration(SessionNSBase):
    # Data stored between webauthn register "begin" and "complete"
    webauthn_state: WebauthnState
    authenticator: AuthenticatorAttachment


class SecurityNS(SessionNSBase):
    # used for new change_password
    generated_password_hash: Optional[str] = None
    # used for update user data from official source
    user_requested_update: Optional[datetime] = None
    webauthn_registration: Optional[WebauthnRegistration] = None


class EmailVerification(SessionNSBase):
    completed: bool = False
    address: Optional[str] = None
    verification_code: Optional[str] = None
    bad_attempts: int = 0
    sent_at: Optional[datetime] = None
    reference: Optional[str] = None


class Invite(SessionNSBase):
    completed: bool = False
    initiated_signup: bool = False
    invite_code: Optional[str] = None
    finish_url: Optional[str] = None


class Tou(SessionNSBase):
    completed: bool = False
    version: Optional[str] = None


class Captcha(SessionNSBase):
    completed: bool = False
    internal_answer: Optional[str] = None
    bad_attempts: int = 0


class Credentials(SessionNSBase):
    completed: bool = False
    password: Optional[str] = None
    webauthn: Optional[Any] = None  # TODO: implement webauthn signup


class Signup(TimestampedNS):
    user_created: bool = False
    email: EmailVerification = Field(default_factory=EmailVerification)
    invite: Invite = Field(default_factory=Invite)
    tou: Tou = Field(default_factory=Tou)
    captcha: Captcha = Field(default_factory=Captcha)
    credentials: Credentials = Field(default_factory=Credentials)


class Phone(SessionNSBase):
    captcha: Captcha = Field(default_factory=Captcha)


RequestRef = NewType("RequestRef", str)


class OnetimeCredType(str, Enum):
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
    aborted: Optional[bool] = False
    used: Optional[bool] = False  # set to True after the request has been completed (to handle 'back' button presses)
    template_show_msg: Optional[str] = (
        None  # set when the template version of the idp should show a message to the user
    )
    # Credentials used while authenticating _this SAML request_. Not ones inherited from SSO.
    credentials_used: dict[ElementKey, datetime] = Field(default_factory=dict)
    onetime_credentials: dict[ElementKey, OnetimeCredential] = Field(default_factory=dict)


class IdP_SAMLPendingRequest(IdP_PendingRequest):
    request: str
    binding: str
    relay_state: Optional[str] = None
    # a pointer to an ongoing request to login using another device
    other_device_state_id: Optional[OtherDeviceId] = None


class IdP_OtherDevicePendingRequest(IdP_PendingRequest):
    state_id: Optional[OtherDeviceId] = None  # can be None on aborted/expired requests


IdP_PendingRequestSubclass = Union[IdP_SAMLPendingRequest, IdP_OtherDevicePendingRequest]


class IdP_Namespace(TimestampedNS):
    # The SSO cookie value last set by the IdP. Used to debug issues with browsers not
    # honoring Set-Cookie in redirects, or something.
    sso_cookie_val: Optional[str] = None
    pending_requests: dict[RequestRef, IdP_PendingRequestSubclass] = Field(default={})

    def log_credential_used(
        self, request_ref: RequestRef, credential: Union[Credential, OnetimeCredential], timestamp: datetime
    ) -> None:
        """Log the credential used in the session, under this particular SAML request"""
        if isinstance(credential, OnetimeCredential):
            self.pending_requests[request_ref].onetime_credentials[credential.key] = credential
        self.pending_requests[request_ref].credentials_used[credential.key] = timestamp


class AuthnParameters(BaseModel):
    force_authn: bool = False  # a new authentication was required
    force_mfa: bool = False  # require MFA even if the user has no token (use Freja or other)
    high_security: bool = False  # opportunistic MFA, request it if the user has a token
    same_user: bool = False  # the same user was required to log in, such as when entering the security center


class BaseAuthnRequest(BaseModel, ABC):
    frontend_state: Optional[str] = None  # opaque data from frontend, returned in /status
    method: Optional[str] = None  # proofing method that frontend is invoking
    frontend_action: str  # what action frontend is performing, decides the finish URL the user is redirected to
    post_authn_action: Optional[Union[AuthnAcsAction, EidasAcsAction, SvipeIDAction, BankIDAcsAction]] = None
    created_ts: datetime = Field(default_factory=utc_now)
    authn_instant: Optional[datetime] = None
    status: Optional[str] = None  # populated by the SAML2 ACS/OIDC callback action
    error: Optional[bool] = None


class SP_AuthnRequest(BaseAuthnRequest):
    credentials_used: list[ElementKey] = Field(default_factory=list)
    # proofing_credential_id is the credential being person-proofed, when doing that
    proofing_credential_id: Optional[ElementKey] = None
    redirect_url: Optional[str] = None  # Deprecated, use frontend_action to get return URL from config instead
    consumed: bool = False  # an operation that requires a new authentication has used this one already
    req_authn_ctx: List[str] = Field(default_factory=list)  # the authentication contexts requested for this authentication
    params: AuthnParameters = Field(default_factory=AuthnParameters)


PySAML2Dicts = NewType("PySAML2Dicts", dict[str, dict[str, Any]])


class SPAuthnData(BaseModel):
    post_authn_action: Optional[Union[AuthnAcsAction, EidasAcsAction, BankIDAcsAction]] = None
    pysaml2_dicts: PySAML2Dicts = Field(default=cast(PySAML2Dicts, dict()))
    authns: dict[AuthnRequestRef, SP_AuthnRequest] = Field(default_factory=dict)

    def get_authn_for_action(self, action: Union[AuthnAcsAction, EidasAcsAction]) -> Optional[SP_AuthnRequest]:
        for authn in self.authns.values():
            if authn.post_authn_action == action:
                return authn
        return None


class EidasNamespace(SessionNSBase):
    # TODO: Move verify_token_action_credential_id into SP_AuthnRequest
    verify_token_action_credential_id: Optional[ElementKey] = None
    sp: SPAuthnData = Field(default=SPAuthnData())


class AuthnNamespace(SessionNSBase):
    sp: SPAuthnData = Field(default=SPAuthnData())
    name_id: Optional[str] = None  # SAML NameID, used in logout
    next: Optional[str] = None


class RP_AuthnRequest(BaseAuthnRequest):
    pass


class RPAuthnData(BaseModel):
    authlib_cache: dict[str, Any] = Field(default_factory=dict)
    authns: dict[OIDCState, RP_AuthnRequest] = Field(default_factory=dict)


class SvipeIDNamespace(SessionNSBase):
    rp: RPAuthnData = Field(default=RPAuthnData())


class BankIDNamespace(SessionNSBase):
    # TODO: Move verify_token_action_credential_id into SP_AuthnRequest
    verify_token_action_credential_id: Optional[ElementKey] = None
    sp: SPAuthnData = Field(default=SPAuthnData())
