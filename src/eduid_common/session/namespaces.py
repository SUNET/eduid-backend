# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from copy import deepcopy
from datetime import datetime

from dataclasses import dataclass, asdict

from typing import Optional
from enum import Enum, unique

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
        if _data.get('ts') is not None:
            _data['ts'] = datetime.fromtimestamp(int(_data['ts']))
        return cls(**_data)


@dataclass
class ResetPasswordNS(SessionNSBase):
    generated_password_hash: Optional[str] = None
    generated_password_salt: Optional[str] = None


@dataclass()
class Signup(TimestampedNS):
    """"""

@dataclass()
class Actions(TimestampedNS):
    session: Optional[str] = None
