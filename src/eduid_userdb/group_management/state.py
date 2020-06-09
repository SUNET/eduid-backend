# -*- coding: utf-8 -*-

import copy
import datetime
from dataclasses import asdict, dataclass, field, fields
from typing import Mapping, MutableMapping, Optional

import bson

from eduid_userdb.exceptions import UserDBValueError

__author__ = 'lundberg'


@dataclass(frozen=True)
class GroupInviteState:
    group_id: str
    email_address: str
    role: str
    id: bson.ObjectId = field(default_factory=bson.ObjectId)
    # Timestamp of last modification in the database.
    # None if GroupInviteState has never been written to the database.
    modified_ts: Optional[datetime.datetime] = None

    @classmethod
    def from_dict(cls, data: Mapping):
        field_names = set(f.name for f in fields(cls))
        _data = copy.deepcopy(dict(data))  # to not modify callers data
        if '_id' in _data:
            _data['id'] = _data.pop('_id')

        # Can not use default args as those will be placed before non default args
        # in inheriting classes
        if not _data.get('id'):
            _data['id'] = None
        if not _data.get('modified_ts'):
            _data['modified_ts'] = None

        _leftovers = [x for x in _data.keys() if x not in field_names]
        if _leftovers:
            raise UserDBValueError(f'{cls}.from_dict() unknown data: {_leftovers}')

        return cls(**_data)

    def to_dict(self) -> MutableMapping:
        res = asdict(self)
        res['_id'] = res.pop('id')
        res['group_id'] = res.pop('group_id')
        res['email_address'] = res.pop('email_address')
        res['role'] = res.pop('role')
        return res

    def __str__(self):
        return f'<eduID {self.__class__.__name__}: group_id={self.group_id} email_address={self.email_address} role={self.role}>'
