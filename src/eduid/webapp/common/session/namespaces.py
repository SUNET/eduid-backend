# -*- coding: utf-8 -*-
from __future__ import annotations

import logging
from abc import ABC
from copy import deepcopy
from datetime import datetime
from enum import Enum, unique
from typing import Any, Dict, List, NewType, Optional, Type, TypeVar, Union
from uuid import uuid4

from pydantic import BaseModel, Field

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.actions import Action
from eduid.userdb.credentials import Credential
from eduid.userdb.credentials.base import CredentialKey

__author__ = 'ft'

from eduid.webapp.common.api.messages import TranslatableMsg

from eduid.webapp.common.authn.acs_enums import AuthnAcsAction, EidasAcsAction

logger = logging.getLogger(__name__)


class SessionNSBase(BaseModel, ABC):
    def to_dict(self) -> Dict[str, Any]:
        return self.dict()

    @classmethod
    def from_dict(cls: Type[SessionNSBase], data) -> TSessionNSSubclass:
        _data = deepcopy(data)  # do not modify callers data
        # Avoid error: Incompatible return value type (got "SessionNSBase", expected "TSessionNSSubclass")
        return cls(**_data)  # type: ignore


TSessionNSSubclass = TypeVar('TSessionNSSubclass', bound=SessionNSBase)


@unique
class LoginApplication(str, Enum):
    idp = 'idp'
    authn = 'authn'
    signup = 'signup'


class Common(SessionNSBase):
    eppn: Optional[str] = None
    is_logged_in: bool = False
    login_source: Optional[LoginApplication] = None
    preferred_language: Optional[str] = None


class MfaAction(SessionNSBase):
    success: bool = False
    error: Optional[TranslatableMsg] = None
    # Third-party MFA parameters
    issuer: Optional[str] = None
    authn_instant: Optional[str] = None
    authn_context: Optional[str] = None
    # Webauthn MFA parameters
    webauthn_state: Optional[Dict[str, Any]] = None


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


class Signup(TimestampedNS):
    email_verification_code: Optional[str] = None


class Actions(TimestampedNS):
    session: Optional[str] = None
    current_plugin: Optional[str] = None
    current_action: Optional[Action] = None
    current_step: Optional[int] = None
    total_steps: Optional[int] = None


RequestRef = NewType('RequestRef', str)


class OnetimeCredType(str, Enum):
    external_mfa = 'ext_mfa'


class OnetimeCredential(BaseModel):
    key: CredentialKey = Field(default_factory=lambda: CredentialKey(str(uuid4())))
    type: OnetimeCredType

    # External MFA auth parameters
    issuer: str
    authn_context: str
    timestamp: datetime


class IdP_PendingRequest(BaseModel):
    request: str
    binding: str
    relay_state: Optional[str]
    template_show_msg: Optional[str]  # set when the template version of the idp should show a message to the user
    # Credentials used while authenticating _this SAML request_. Not ones inherited from SSO.
    credentials_used: Dict[CredentialKey, datetime] = Field(default={})
    onetime_credentials: Dict[CredentialKey, OnetimeCredential] = Field(default={})


class IdP_Namespace(TimestampedNS):
    # The SSO cookie value last set by the IdP. Used to debug issues with browsers not
    # honoring Set-Cookie in redirects, or something.
    sso_cookie_val: Optional[str] = None
    pending_requests: Dict[RequestRef, IdP_PendingRequest] = Field(default={})

    def log_credential_used(
        self, request_ref: RequestRef, credential: Union[Credential, OnetimeCredential], timestamp: datetime
    ) -> None:
        """ Log the credential used in the session, under this particular SAML request """
        if isinstance(credential, OnetimeCredential):
            self.pending_requests[request_ref].onetime_credentials[credential.key] = credential
        self.pending_requests[request_ref].credentials_used[credential.key] = timestamp


class SP_AuthnRequest(BaseModel):
    redirect_url: str
    post_authn_action: Optional[Union[AuthnAcsAction, EidasAcsAction]] = None
    credentials_used: List[CredentialKey] = Field(default=[])
    created_ts: datetime = Field(default_factory=utc_now)
    authn_instant: Optional[datetime] = None


AuthnRequestRef = NewType('AuthnRequestRef', str)


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

    verify_token_action_credential_id: Optional[CredentialKey] = None
    sp: SPAuthnData = Field(default=SPAuthnData())


class Authn_Namespace(SessionNSBase):

    sp: SPAuthnData = Field(default=SPAuthnData())
    name_id: Optional[str] = None  # SAML NameID, used in logout
    next: Optional[str] = None
