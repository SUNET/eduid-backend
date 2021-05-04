# -*- coding: utf-8 -*-
from __future__ import annotations

from abc import ABC
from copy import deepcopy
from datetime import datetime
from enum import Enum, unique
from typing import Any, Dict, Optional, Type, TypeVar

__author__ = 'ft'

from pydantic import BaseModel, Field

from eduid.common.misc.timeutil import utc_now


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

    def to_dict(self):
        res = self.dict()
        return res

    @classmethod
    def from_dict(cls, data):
        _data = deepcopy(data)  # do not modify callers data
        if _data.get('login_source') is not None:
            _data['login_source'] = LoginApplication(_data['login_source'])
        return cls(**_data)


class MfaAction(SessionNSBase):
    success: bool = False
    issuer: Optional[str] = None
    authn_instant: Optional[str] = None
    authn_context: Optional[str] = None


class TimestampedNS(SessionNSBase):
    ts: datetime = Field(utc_now())

    def to_dict(self) -> Dict[str, Any]:
        res = super().to_dict()
        res['ts'] = self.ts.isoformat()
        return res


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


class SAMLData(BaseModel):
    request: str
    relay_state: Optional[str]
    key: str  # sha1 of request


class IdP_Namespace(TimestampedNS):
    # The SSO cookie value last set by the IdP. Used to debug issues with browsers not
    # honoring Set-Cookie in redirects, or something.
    sso_cookie_val: Optional[str] = None
