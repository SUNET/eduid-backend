# -*- coding: utf-8 -*-

from __future__ import annotations

import copy
import datetime
from dataclasses import asdict, dataclass, field, fields
from enum import Enum, unique
from typing import Any, Dict, Mapping, Optional

import bson

from eduid.userdb.exceptions import UserDBValueError

__author__ = 'lundberg'


@unique
class GroupRole(Enum):
    OWNER = 'owner'
    MEMBER = 'member'


@dataclass(frozen=True)
class GroupInviteState:
    group_scim_id: str
    email_address: str
    role: GroupRole
    inviter_eppn: str
    id: bson.ObjectId = field(default_factory=bson.ObjectId)
    # Timestamp of last modification in the database.
    # None if GroupInviteState has never been written to the database.
    modified_ts: Optional[datetime.datetime] = None

    @classmethod
    def from_dict(cls, data: Mapping) -> GroupInviteState:
        _data = copy.deepcopy(dict(data))  # to not modify callers data
        if '_id' in _data:
            _data['id'] = _data.pop('_id')
        if 'role' in _data:
            _data['role'] = GroupRole(_data['role'])

        # Can not use default args as those will be placed before non default args
        # in inheriting classes
        if not _data.get('id'):
            _data['id'] = None
        if not _data.get('modified_ts'):
            _data['modified_ts'] = None

        field_names = set(f.name for f in fields(cls))
        _leftovers = [x for x in _data.keys() if x not in field_names]
        if _leftovers:
            raise UserDBValueError(f'{cls}.from_dict() unknown data: {_leftovers}')

        return cls(**_data)

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res['_id'] = res.pop('id')
        res['role'] = res['role'].value
        return res

    def __str__(self) -> str:
        return (
            f'<eduID {self.__class__.__name__}: group_scim_id={self.group_scim_id} '
            f'email_address={self.email_address} role={self.role.value}>'
        )
