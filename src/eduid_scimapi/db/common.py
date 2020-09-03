# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Mapping, Optional, Type, Union

from eduid_scimapi.schemas.scimbase import EmailType, PhoneNumberType

__author__ = 'lundberg'


@dataclass
class Profile:
    attributes: Dict[str, Any] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Mapping[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls: Type[Profile], data: Mapping[str, Any]) -> Profile:
        _attributes = data.get('attributes', {})
        _data = data.get('data', {})
        return cls(attributes=_attributes, data=_data)


@dataclass
class Name:
    familyName: Optional[str] = None
    givenName: Optional[str] = None
    formatted: Optional[str] = None
    middleName: Optional[str] = None
    honorificPrefix: Optional[str] = None
    honorificSuffix: Optional[str] = None

    def to_dict(self) -> Mapping[str, Optional[str]]:
        return asdict(self)

    @classmethod
    def from_dict(cls: Type[Name], data: Mapping[str, Optional[str]]) -> Name:
        return cls(**data)


@dataclass
class Email:
    value: str
    display: Optional[str] = None
    type: Optional[EmailType] = None
    primary: Optional[bool] = None

    def to_dict(self) -> Mapping[str, Union[Optional[str], bool]]:
        res = asdict(self)
        if self.type is not None:
            res['type'] = self.type.value
        return res

    @classmethod
    def from_dict(cls: Type[Email], data: Mapping[str, Any]) -> Email:
        email_type = None
        if data.get('type') is not None:
            email_type = EmailType(data['type'])
        return cls(value=data['value'], display=data.get('display'), type=email_type, primary=data.get('primary'))


@dataclass
class PhoneNumber:
    value: str
    display: Optional[str] = None
    type: Optional[PhoneNumberType] = None
    primary: Optional[bool] = None

    def to_dict(self) -> Mapping[str, Union[Optional[str], bool]]:
        res = asdict(self)
        if self.type is not None:
            res['type'] = self.type.value
        return res

    @classmethod
    def from_dict(cls: Type[PhoneNumber], data: Mapping[str, Any]) -> PhoneNumber:
        number_type = None
        if data.get('type') is not None:
            number_type = PhoneNumberType(data['type'])
        return cls(value=data['value'], display=data.get('display'), type=number_type, primary=data.get('primary'))
