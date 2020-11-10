# -*- coding: utf-8 -*-

from abc import ABC
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum, unique
from typing import Optional

__author__ = 'ft'


class SessionNSBase(ABC):
    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        _data = deepcopy(data)  # do not modify callers data
        return cls(**_data)


@unique
class LoginApplication(Enum):
    idp = 'idp'
    authn = 'authn'
    signup = 'signup'


@dataclass()
class Common(SessionNSBase):
    eppn: Optional[str] = None
    is_logged_in: bool = False
    login_source: Optional[LoginApplication] = None

    def to_dict(self):
        res = asdict(self)
        if res.get('login_source') is not None:
            res['login_source'] = res['login_source'].value
        return res

    @classmethod
    def from_dict(cls, data):
        _data = deepcopy(data)  # do not modify callers data
        if _data.get('login_source') is not None:
            _data['login_source'] = LoginApplication(_data['login_source'])
        return cls(**_data)


@dataclass()
class MfaAction(SessionNSBase):
    success: bool = False
    issuer: Optional[str] = None
    authn_instant: Optional[str] = None
    authn_context: Optional[str] = None


@dataclass()
class TimestampedNS(SessionNSBase):
    ts: Optional[datetime] = None

    def to_dict(self):
        res = super(TimestampedNS, self).to_dict()
        if res.get('ts') is not None:
            res['ts'] = str(int(res['ts'].timestamp()))
        return res

    @classmethod
    def from_dict(cls, data):
        _data = deepcopy(data)  # do not modify callers data
        _ts = _data.get('ts')
        if _ts is not None:
            # Load timestamp from ISO format string, or fallback to old UNIX time.
            # When this code is deployed everywhere, we can change to ISO format in to_dict above.
            if isinstance(_ts, str):
                _data['ts'] = datetime.fromisoformat(_ts)
            else:
                _data['ts'] = datetime.fromtimestamp(int(_ts))
        return cls(**_data)


@dataclass
class ResetPasswordNS(SessionNSBase):
    generated_password_hash: Optional[str] = None
    # XXX the keys below are not in use yet. They are set in eduid-common,
    # in a way that the security app understands. Once the (reset|change)
    # password views are removed from the security app, we will be able to
    # start using them. The session key reauthn-for-chpass is in the same
    # situation.
    extrasec_u2f_challenge: Optional[str] = None
    extrasec_webauthn_state: Optional[str] = None


@dataclass()
class Signup(TimestampedNS):
    email_verification_code: Optional[str] = None


@dataclass()
class Actions(TimestampedNS):
    session: Optional[str] = None


@dataclass()
class IdP_Namespace(TimestampedNS):
    # The SSO cookie value last set by the IdP. Used to debug issues with browsers not
    # honoring Set-Cookie in redirects, or something.
    sso_cookie_val: Optional[str] = None
