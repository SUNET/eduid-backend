# -*- coding: utf-8 -*-

from __future__ import annotations

import datetime
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional, Type, TypeVar, Union

import bson

from eduid_userdb.deprecation import deprecated
from eduid_userdb.security.element import CodeElement

__author__ = 'lundberg'


TPasswordResetStateSubclass = TypeVar('TPasswordResetStateSubclass', bound='PasswordResetState')


@dataclass
class PasswordResetState(object):
    eppn: str
    id: bson.ObjectId = field(default_factory=lambda: bson.ObjectId())
    reference: str = field(init=False)
    method: Optional[str] = None
    created_ts: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    modified_ts: Optional[datetime.datetime] = None
    extra_security: Optional[Dict[str, Any]] = None
    generated_password: bool = False

    @deprecated("Remove once the password reset views are served from their own webapp")
    def __post_init__(self):
        self.reference = str(self.id)

    def __str__(self):
        return '<eduID {!s}: {!s}>'.format(self.__class__.__name__, self.eppn)

    def to_dict(self) -> dict:
        res = asdict(self)
        res['eduPersonPrincipalName'] = res.pop('eppn')
        res['_id'] = res.pop('id')
        return res

    @classmethod
    def from_dict(cls: Type[TPasswordResetStateSubclass], data: Dict[str, Any]) -> TPasswordResetStateSubclass:
        data['eppn'] = data.pop('eduPersonPrincipalName')
        data['id'] = data.pop('_id')
        if 'reference' in data:
            data.pop('reference')
        return cls(**data)


@dataclass
class _PasswordResetEmailStateRequired:
    """
    """

    email_address: str
    email_code: Union[str, CodeElement]


@dataclass
class PasswordResetEmailState(PasswordResetState, _PasswordResetEmailStateRequired):
    @deprecated("Remove once the password reset views are served from their own webapp")
    def __post_init__(self):
        super().__post_init__()
        self.method = 'email'
        self.email_code = CodeElement.parse(application='security', code_or_element=self.email_code)

    def to_dict(self):
        res = super().to_dict()
        # This check is to please mypy, email_code can only be a string briefly during initialization
        if isinstance(self.email_code, CodeElement):
            res['email_code'] = self.email_code.to_dict()
        return res


@dataclass
class _PasswordResetEmailAndPhoneStateRequired:
    """
    """

    phone_number: str
    phone_code: Union[str, CodeElement]


@dataclass
class PasswordResetEmailAndPhoneState(PasswordResetEmailState, _PasswordResetEmailAndPhoneStateRequired):
    @deprecated("Remove once the password reset views are served from their own webapp")
    def __post_init__(self):
        super().__post_init__()
        self.method = 'email_and_phone'
        self.phone_code = CodeElement.parse(application='security', code_or_element=self.phone_code)

    @classmethod
    def from_email_state(
        cls, email_state: PasswordResetEmailState, phone_number: str, phone_code: str
    ) -> PasswordResetEmailAndPhoneState:
        data = email_state.to_dict()
        data['phone_number'] = phone_number
        data['phone_code'] = phone_code
        return cls.from_dict(data=data)

    def to_dict(self) -> dict:
        res = super().to_dict()
        # This check is to please mypy, phone_code can only be a string briefly during initialization
        if self.phone_code and isinstance(self.phone_code, CodeElement):
            res['phone_code'] = self.phone_code.to_dict()
        return res
