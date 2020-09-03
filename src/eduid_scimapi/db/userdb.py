from __future__ import annotations

import copy
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Tuple, Type
from uuid import UUID

from bson import ObjectId

from eduid_scimapi.db.basedb import ScimApiBaseDB
from eduid_scimapi.db.common import ScimApiProfile

__author__ = 'ft'


logger = logging.getLogger(__name__)


@dataclass
class ScimApiUser:
    user_id: ObjectId = field(default_factory=lambda: ObjectId())
    scim_id: UUID = field(default_factory=lambda: uuid.uuid4())
    external_id: Optional[str] = None
    version: ObjectId = field(default_factory=lambda: ObjectId())
    created: datetime = field(default_factory=lambda: datetime.utcnow())
    last_modified: datetime = field(default_factory=lambda: datetime.utcnow())
    profiles: Dict[str, ScimApiProfile] = field(default_factory=lambda: {})

    @property
    def etag(self):
        return f'W/"{self.version}"'

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res['scim_id'] = str(res['scim_id'])
        res['_id'] = res.pop('user_id')
        return res

    @classmethod
    def from_dict(cls: Type[ScimApiUser], data: Mapping[str, Any]) -> ScimApiUser:
        this = dict(copy.copy(data))  # to not modify callers data
        this['scim_id'] = uuid.UUID(this['scim_id'])
        this['user_id'] = this.pop('_id')
        # Profiles
        parsed_profiles = {}
        for k, v in data['profiles'].items():
            parsed_profiles[k] = ScimApiProfile.from_dict(v)
        this['profiles'] = parsed_profiles
        return cls(**this)


class ScimApiUserDB(ScimApiBaseDB):
    def __init__(self, db_uri: str, collection: str, db_name='eduid_scimapi'):
        super().__init__(db_uri, db_name, collection=collection)
        # Create an index so that scim_id and external_id is unique per data owner
        indexes = {
            'unique-scimid': {'key': [('scim_id', 1)], 'unique': True},
            'unique-external-id': {'key': [('external_id', 1)], 'unique': True},
        }
        self.setup_indexes(indexes)

    def save(self, user: ScimApiUser) -> bool:
        user_dict = user.to_dict()

        if 'profiles' in user_dict:
            # don't save the special PoC eduid profiles in the database (bson does not allow dots in keys)
            for eduid_domain in ['eduid.se', 'dev.eduid.se']:
                if eduid_domain in user_dict['profiles']:
                    del user_dict['profiles'][eduid_domain]

        test_doc = {
            '_id': user.user_id,
            'version': user.version,
        }
        # update the version number and last_modified timestamp
        user_dict['version'] = ObjectId()
        user_dict['last_modified'] = datetime.utcnow()
        result = self._coll.replace_one(test_doc, user_dict, upsert=False)
        if result.modified_count == 0:
            db_user = self._coll.find_one({'_id': user.user_id})
            if db_user:
                logger.debug(f'{self} FAILED Updating user {user} in {self._coll_name}')
                raise RuntimeError('User out of sync, please retry')
            self._coll.insert_one(user_dict)
        # put the new version number and last_modified in the user object after a successful update
        user.version = user_dict['version']
        user.last_modified = user_dict['last_modified']
        logger.debug(f'{self} Updated user {user} in {self._coll_name}')
        import pprint

        extra_debug = pprint.pformat(user_dict, width=120)
        logger.debug(f'Extra debug:\n{extra_debug}')

        return result.acknowledged

    def remove(self, user: ScimApiUser):
        return self.remove_document(user.user_id)

    # TODO: Not working, remove/rewrite?
    def get_user_by_eduid_eppn(self, eppn: str) -> Optional[ScimApiUser]:
        return self.get_user_by_scoped_attribute('eduid', 'external_id', eppn)

    def get_user_by_scim_id(self, scim_id: str) -> Optional[ScimApiUser]:
        docs = self._get_document_by_attr('scim_id', scim_id, raise_on_missing=False)
        if docs:
            return ScimApiUser.from_dict(docs)
        return None

    def get_user_by_external_id(self, external_id: str) -> Optional[ScimApiUser]:
        docs = self._get_document_by_attr('external_id', external_id, raise_on_missing=False)
        if docs:
            return ScimApiUser.from_dict(docs)
        return None

    # TODO: Not used, remove?
    def get_user_by_scoped_attribute(self, scope: str, attr: str, value: Any) -> Optional[ScimApiUser]:
        docs = self._get_documents_by_filter(spec={f'profiles.{scope}.{attr}': value}, raise_on_missing=False)
        if len(docs) == 1:
            return ScimApiUser.from_dict(docs[0])
        return None

    def get_users_by_last_modified(
        self, operator: str, value: datetime, limit: Optional[int] = None, skip: Optional[int] = None
    ) -> Tuple[List[ScimApiUser], int]:
        # map SCIM filter operators to mongodb filter
        mongo_operator = {'gt': '$gt', 'ge': '$gte'}.get(operator)
        if not mongo_operator:
            raise ValueError('Invalid filter operator')
        spec = {'last_modified': {mongo_operator: value}}
        docs, total_count = self._get_documents_and_count_by_filter(spec=spec, limit=limit, skip=skip)
        users = [ScimApiUser.from_dict(x) for x in docs]
        return users, total_count

    def user_exists(self, scim_id: str) -> bool:
        return bool(self.db_count(spec={'scim_id': scim_id}, limit=1))
