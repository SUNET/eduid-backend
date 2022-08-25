# -*- coding: utf-8 -*-
from __future__ import annotations

import logging
from abc import ABC
from copy import deepcopy
from datetime import datetime
from enum import Enum, unique
from typing import Any, Dict, List, Mapping, NewType, Optional, Type, TypeVar, Union
from uuid import uuid4

from pydantic import BaseModel, Field, ValidationError

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.actions import Action
from eduid.userdb.credentials import Credential

__author__ = 'ft'

from eduid.userdb.credentials.external import TrustFramework
from eduid.userdb.credentials.fido import WebauthnAuthenticator
from eduid.userdb.element import ElementKey
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction, EidasAcsAction
from eduid.webapp.eidas.helpers import EidasMsg
from eduid.webapp.idp.other_device.data import OtherDeviceId

logger = logging.getLogger(__name__)


AuthnRequestRef = NewType('AuthnRequestRef', str)


class SessionNSBase(BaseModel, ABC):
    def to_dict(self) -> Dict[str, Any]:
        return self.dict()

    @classmethod
    def from_dict(cls: Type[SessionNSBase], data) -> TSessionNSSubclass:
        _data = cls._from_dict_transform(data)

        # Avoid error: Incompatible return value type (got "SessionNSBase", expected "TSessionNSSubclass")
        try:
            return cls(**_data)  # type: ignore
        except ValidationError:
            logger.warning(f'Could not parse session namespace:\n{_data}')
            raise

    @classmethod
    def _from_dict_transform(cls: Type[SessionNSBase], data: Mapping[str, Any]) -> Dict[str, Any]:
        _data = deepcopy(data)  # do not modify callers data
        return dict(_data)


TSessionNSSubclass = TypeVar('TSessionNSSubclass', bound=SessionNSBase)


@unique
class LoginApplication(str, Enum):
    idp = 'idp'
    authn = 'authn'
    signup = 'signup'


@unique
class MfaActionError(str, Enum):
    authn_context_mismatch = 'authn_context_mismatch'
    authn_too_old = 'authn_too_old'
    nin_not_matching = 'nin_not_matching'
    foreign_eid_not_matching = 'foreign_eid_not_matching'


class Common(SessionNSBase):
    eppn: Optional[str] = None
    is_logged_in: bool = False
    login_source: Optional[LoginApplication] = None
    preferred_language: Optional[str] = None


WebauthnState = NewType('WebauthnState', Dict[str, Any])


class MfaAction(SessionNSBase):
    success: bool = False
    error: Optional[MfaActionError] = None
    login_ref: Optional[str] = None
    authn_req_ref: Optional[AuthnRequestRef] = None
    credential_used: Optional[ElementKey] = None
    # Third-party MFA parameters
    framework: Optional[TrustFramework] = None
    required_loa: List[str] = Field(default_factory=list)
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
    authenticator: WebauthnAuthenticator


class SecurityNS(SessionNSBase):
    # used for new change_password
    generated_password_hash: Optional[str] = None
    # used for update user data from official source
    user_requested_update: Optional[datetime] = None
    webauthn_registration: Optional[WebauthnRegistration] = None


class Signup(TimestampedNS):
    email_verification_code: Optional[str] = None


# TODO: Remove Actions, should be unused
class Actions(TimestampedNS):
    session: Optional[str] = None
    current_plugin: Optional[str] = None
    current_action: Optional[Action] = None
    current_step: Optional[int] = None
    total_steps: Optional[int] = None


RequestRef = NewType('RequestRef', str)


class OnetimeCredType(str, Enum):
    external_mfa = 'ext_mfa'


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
    template_show_msg: Optional[str]  # set when the template version of the idp should show a message to the user
    # Credentials used while authenticating _this SAML request_. Not ones inherited from SSO.
    credentials_used: Dict[ElementKey, datetime] = Field(default={})
    onetime_credentials: Dict[ElementKey, OnetimeCredential] = Field(default={})


class IdP_SAMLPendingRequest(IdP_PendingRequest):
    request: str
    binding: str
    relay_state: Optional[str]
    # a pointer to an ongoing request to login using another device
    other_device_state_id: Optional[OtherDeviceId] = None


class IdP_OtherDevicePendingRequest(IdP_PendingRequest):
    state_id: Optional[OtherDeviceId]  # can be None on aborted/expired requests


class IdP_Namespace(TimestampedNS):
    # The SSO cookie value last set by the IdP. Used to debug issues with browsers not
    # honoring Set-Cookie in redirects, or something.
    sso_cookie_val: Optional[str] = None
    pending_requests: Dict[RequestRef, IdP_PendingRequest] = Field(default={})

    @classmethod
    def _from_dict_transform(cls: Type[IdP_Namespace], data: Mapping[str, Any]) -> Dict[str, Any]:
        _data = super()._from_dict_transform(data)
        if 'pending_requests' in _data:
            # pre-parse values into the right subclass if IdP_PendingRequest
            for k, v in _data['pending_requests'].items():
                if 'binding' in v:
                    _data['pending_requests'][k] = IdP_SAMLPendingRequest(**v)
                elif 'state_id' in v:
                    _data['pending_requests'][k] = IdP_OtherDevicePendingRequest(**v)
        return _data

    def log_credential_used(
        self, request_ref: RequestRef, credential: Union[Credential, OnetimeCredential], timestamp: datetime
    ) -> None:
        """Log the credential used in the session, under this particular SAML request"""
        if isinstance(credential, OnetimeCredential):
            self.pending_requests[request_ref].onetime_credentials[credential.key] = credential
        self.pending_requests[request_ref].credentials_used[credential.key] = timestamp


class SP_AuthnRequest(BaseModel):
    redirect_url: str
    post_authn_action: Optional[Union[AuthnAcsAction, EidasAcsAction]] = None
    credentials_used: List[ElementKey] = Field(default=[])
    created_ts: datetime = Field(default_factory=utc_now)
    authn_instant: Optional[datetime] = None
    # login_ref is used when logging in
    frontend_state: Optional[str] = None
    # proofing_credential_id is the credential being person-proofed, when doing that
    proofing_credential_id: Optional[ElementKey] = None
    # Third-party MFA parameters
    method: Optional[str] = None
    error: Optional[EidasMsg] = None  # populated by the SAML2 ACS


class SPAuthnData(BaseModel):
    post_authn_action: Optional[Union[AuthnAcsAction, EidasAcsAction]] = None
    pysaml2_dicts: Dict[str, Any] = Field(default={})
    authns: Dict[AuthnRequestRef, SP_AuthnRequest] = Field(default={})

    def get_authn_for_action(self, action: Union[AuthnAcsAction, EidasAcsAction]) -> Optional[SP_AuthnRequest]:
        for authn in self.authns.values():
            if authn.post_authn_action == action:
                return authn
        return None


class Eidas_Namespace(SessionNSBase):

    # TODO: Move verify_token_action_credential_id into SP_AuthnRequest
    verify_token_action_credential_id: Optional[ElementKey] = None
    sp: SPAuthnData = Field(default=SPAuthnData())


class Authn_Namespace(SessionNSBase):

    sp: SPAuthnData = Field(default=SPAuthnData())
    name_id: Optional[str] = None  # SAML NameID, used in logout
    next: Optional[str] = None
