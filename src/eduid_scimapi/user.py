from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, Mapping, Optional, Type
from uuid import UUID

from bson import ObjectId

from eduid_scimapi.profile import Profile
from eduid_scimapi.scimbase import SCIMSchema

__author__ = 'ft'


@dataclass
class ScimApiUser(object):
    user_id: ObjectId = field(default_factory=lambda: ObjectId())
    scim_id: UUID = field(default_factory=lambda: uuid.uuid4())
    external_id: Optional[str] = None
    version: ObjectId = field(default_factory=lambda: ObjectId())
    created: datetime = field(default_factory=lambda: datetime.utcnow())
    last_modified: datetime = field(default_factory=lambda: datetime.utcnow())
    profiles: Dict[str, Profile] = field(default_factory=lambda: {})

    @property
    def etag(self):
        return f'W/"{self.version}"'

    def to_scim_dict(self, location: str, debug: bool = False, data_owner: Optional[str] = None) -> Mapping[str, Any]:
        res: Dict[str, Any] = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'id': str(self.scim_id),
            'meta': {
                'resourceType': 'User',
                'created': self.created.isoformat(),
                'lastModified': self.last_modified.isoformat(),
                'location': location,
                'version': self.etag,
            },
        }
        if self.external_id is not None:
            res['externalId'] = self.external_id
        if self.profiles:
            res['schemas'] += [SCIMSchema.NUTID_V1.value]
            if SCIMSchema.NUTID_V1.value not in res:
                res[SCIMSchema.NUTID_V1.value] = {}
            for prof in self.profiles.keys():
                res[SCIMSchema.NUTID_V1.value][prof] = self.profiles[prof].to_schema_dict(SCIMSchema.NUTID_V1.value)
        if debug:
            profiles_dicts = {}
            for this in self.profiles.keys():
                profiles_dicts[this] = asdict(self.profiles[this])
            res['schemas'] += [SCIMSchema.DEBUG_V1.value]
            res[SCIMSchema.DEBUG_V1.value] = {
                'profiles': profiles_dicts,
                'logged_in_as': data_owner,
            }

        return res

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res['scim_id'] = str(res['scim_id'])
        res['_id'] = res.pop('user_id')
        return res

    @classmethod
    def from_dict(cls: Type[ScimApiUser], data: Mapping[str, Any]) -> ScimApiUser:
        this = dict(data)
        this['scim_id'] = uuid.UUID(this['scim_id'])
        this['user_id'] = this.pop('_id')
        parsed_profiles = {}
        for k, v in this['profiles'].items():
            parsed_profiles[k] = Profile(**v)
        this['profiles'] = parsed_profiles
        return cls(**this)
