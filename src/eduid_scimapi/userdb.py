from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, Mapping, Optional, Type
from uuid import UUID

from bson import ObjectId

from eduid_userdb.db import BaseDB

__author__ = 'ft'


# schemas
NUTID_V1 = 'https://scim.eduid.se/schema/nutid/v1'
DEBUG_ALL_V1 = 'https://scim.eduid.se/schema/debug-all-profiles/v1'


logger = logging.getLogger(__name__)


@dataclass()
class Profile():
    external_id: str
    data: Dict[str, Any]

    def to_schema_dict(self, schema: str) -> Mapping[str, Any]:
        res = {}
        if schema == NUTID_V1:
            if 'display_name' in self.data:
                res['displayName'] = self.data['display_name']
        return res


@dataclass
class ScimApiUser(object):
    user_id: ObjectId = field(default_factory=lambda: ObjectId())
    scim_id: UUID = field(default_factory=lambda: uuid.uuid4())
    version: ObjectId = field(default_factory=lambda: ObjectId())
    created: datetime = field(default_factory=lambda: datetime.utcnow())
    last_modified: datetime = field(default_factory=lambda: datetime.utcnow())
    profiles: Dict[str, Profile] = field(default_factory=lambda: {})

    @property
    def etag(self):
        return f'W/"{self.version}"'

    @property
    def external_id(self) -> Optional[str]:
        if 'eduid' in self.profiles:
            _eppn = self.profiles['eduid'].external_id
            return f'{_eppn}@eduid.se'
        return None

    def to_dict(self, location: str, debug: bool = False) -> Mapping[str, Any]:
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
        if self.external_id:
            res['externalId'] = self.external_id
        if 'eduid' in self.profiles:
            res['schemas'] += [NUTID_V1]
            res[NUTID_V1] = self.profiles['eduid'].to_schema_dict(NUTID_V1)
        if debug:
            profiles_dicts = {}
            for this in self.profiles.keys():
                profiles_dicts[this] = asdict(self.profiles[this])
            res['schemas'] += [DEBUG_ALL_V1]
            res[DEBUG_ALL_V1] = profiles_dicts
        return res

    @classmethod
    def from_user_doc(cls: Type[ScimApiUser], data: Mapping[str, Any]) -> ScimApiUser:
        this = dict(data)
        this['scim_id'] = uuid.UUID(this['scim_id'])
        this['user_id'] = this.pop('_id')
        parsed_profiles = {}
        for k,v in this['profiles'].items():
            parsed_profiles[k] = Profile(**v)
        this['profiles'] = parsed_profiles
        return cls(**this)


class ScimApiUserDB(BaseDB):

    def __init__(self, db_uri, db_name='eduid_scimapi', collection='profiles'):
        super().__init__(db_uri, db_name, collection)

    def save(self, user: ScimApiUser) -> bool:
        user_as_dict = asdict(user)
        user_as_dict['scim_id'] = str(user_as_dict['scim_id'])
        user_as_dict['_id'] = user_as_dict.pop('user_id')

        test_doc = {'_id': user.user_id,
                    'version': user.version,
                    }
        # update the version number
        user_as_dict['version'] = ObjectId()
        result = self._coll.replace_one(test_doc, user_as_dict, upsert=False)
        if result.modified_count == 0:
            db_user = self._coll.find_one({'_id': user.user_id})
            if db_user:
                logger.debug(f'{self} FAILED Updating user {user} in {self._coll_name}')
                raise RuntimeError('User out of sync, please retry')
            self._coll.insert_one(user_as_dict)
        # put the new version number in the user object after a successful update
        user.version = user_as_dict['version']
        logger.debug(f'{self} Updated user {user} in {self._coll_name}')
        import pprint
        extra_debug = pprint.pformat(user_as_dict)
        logger.debug(f'Extra debug:\n{extra_debug}')

        return result.acknowledged

    def get_user_by_eduid_eppn(self, eppn: str) -> Optional[ScimApiUser]:
        return self.get_user_by_scoped_attribute('eduid', 'external_id', eppn)

    def get_user_by_scim_id(self, scim_id: str) -> Optional[ScimApiUser]:
        docs = self._get_document_by_attr('scim_id', scim_id, raise_on_missing=False)
        if docs:
            return ScimApiUser.from_user_doc(docs)
        return None

    def get_user_by_scoped_attribute(self, scope: str, attr: str, value: Any) -> Optional[ScimApiUser]:
        docs = self._get_documents_by_filter(spec={f'profiles.{scope}.{attr}': value}, raise_on_missing=False)
        if len(docs) == 1:
            return ScimApiUser.from_user_doc(docs[0])
        return None
