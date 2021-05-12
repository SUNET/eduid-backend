# -*- coding: utf-8 -*-
from __future__ import annotations

from abc import ABC
from copy import deepcopy
from datetime import datetime
from enum import Enum, unique
from typing import Any, Dict, NewType, Optional, Type, TypeVar

__author__ = 'ft'

from pydantic import BaseModel, Field

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials import Credential
from eduid.userdb.credentials.base import CredentialKey


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
    issuer: Optional[str] = None
    authn_instant: Optional[str] = None
    authn_context: Optional[str] = None


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


RequestRef = NewType('RequestRef', str)
ReqSHA1 = NewType('ReqSHA1', str)


class SAMLData(BaseModel):
    request: str
    binding: str
    relay_state: Optional[str]
    key: ReqSHA1  # sha1 of request
    template_show_msg: Optional[str]  # set when the template version of the idp should show a message to the user
    # Credentials used while authenticating _this SAML request_. Not ones inherited from SSO.
    credentials_used: Dict[CredentialKey, datetime] = Field(default={})


class IdP_Namespace(TimestampedNS):
    # The SSO cookie value last set by the IdP. Used to debug issues with browsers not
    # honoring Set-Cookie in redirects, or something.
    sso_cookie_val: Optional[str] = None
    pending_requests: Dict[RequestRef, SAMLData] = Field(default={})

    def log_credential_used(self, key: ReqSHA1, credential: Credential, timestamp: datetime) -> None:
        # Log the credential used in the session, under this particular SAML request
        for this in self.pending_requests.values():
            if this.key == key:
                this.credentials_used[credential.key] = timestamp

    def get_requestref_for_reqsha1(self, key: ReqSHA1) -> Optional[RequestRef]:
        """ Helper function while we still use ReqSHA1 (key) """
        for ref, this in self.pending_requests.items():
            if this.key == key:
                return ref
        return None
