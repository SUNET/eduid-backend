from __future__ import annotations

from dataclasses import asdict
from enum import Enum, unique
from typing import Any, Dict, Mapping, Optional, Union

from bson import ObjectId
from eduid_userdb.db import BaseDB
from loguru import logger
from pydantic.dataclasses import dataclass


@unique
class Status(str, Enum):
    ACTIVE: str = 'active'
    REVOKED: str = 'revoked'


@unique
class Version(str, Enum):
    NDNv1: str = 'NDNv1'


@unique
class KDF(str, Enum):
    PBKDF2_HMAC_SHA512: str = 'PBKDF2-HMAC-SHA512'


class Type(str, Enum):
    PASSWORD: str = 'password'


class CredentialPydanticConfig:
    # only check that obj_id is an instance of ObjectId
    arbitrary_types_allowed = True


@dataclass(config=CredentialPydanticConfig)
class Credential:
    credential_id: str
    derived_key: str
    iterations: int
    kdf: KDF
    key_handle: int
    revision: int
    salt: str
    status: Status
    type: Type
    version: Version
    obj_id: Optional[ObjectId] = None

    @classmethod
    def from_dict(cls: Type[Credential], data: Mapping[str, Any]) -> Credential:
        """ Construct element from a data dict in database format. """

        _data = dict(data)  # to not modify callers data
        if 'credential' in _data:
            # move contents from 'credential' to top-level of dict
            _data.update(_data.pop('credential'))
        if '_id' in _data:
            # Not supported with pydantic dataclasses:
            #   RuntimeWarning: fields may not start with an underscore, ignoring "_id"
            _data['obj_id'] = _data.pop('_id')
        return cls(**_data)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert instance to database format.

        Example of database format:

        {
            '_id': ObjectId('54042b7a9b3f2299bb9d5546'),
            'credential': {
                'status': 'active',
                'derived_key': '65d27b345ceafe533c3314e021517a84be921fa545366a755d998d140bb6e596fd8'
                '7b61296a60eb8a17a1523350869ee97b581a1b75ba77b3d625d3281186fc5',
                'version': 'NDNv1',
                'iterations': 50000,
                'key_handle': 8192,
                'salt': 'd393c00d56d3c6f0fcf32421395427d2',
                'kdf': 'PBKDF2-HMAC-SHA512',
                'type': 'password',
                'credential_id': '54042b7aafce77049473096a',
            },
            'revision': 1,
        }
        """
        data = asdict(self)
        # Convert Enums to their values
        for k in data.keys():
            if isinstance(data[k], Enum):
                data[k] = data[k].value
        # Extract the _id and revision
        obj_id = data.pop('obj_id')
        revision = data.pop('revision')
        return {
            '_id': obj_id,
            'revision': revision,
            'credential': data,
        }


class CredentialDB(BaseDB):
    def __init__(self, db_uri: str, db_name: str = 'vccs_auth_credstore', collection: str = 'credentials'):
        super().__init__(db_uri, db_name, collection=collection)

        indexes = {
            'unique-credential-id': {'key': [('credential.credential_id', 1)], 'unique': True},
        }
        self.setup_indexes(indexes)

    def remove_credential(self, credential: Credential) -> Union[int, bool]:
        """
        Remove entries when SLO is executed.
        :return: False on failure
        """
        res = self._coll.remove({'credential.credential_id': credential.credential_id}, w='majority')
        try:
            return int(res['n'])  # number of deleted records
        except (KeyError, TypeError):
            logger.warning(f'Remove credential {repr(credential.credential_id)} failed, result: {repr(res)}')
            return False

    def save(self, credential: Credential) -> None:
        """
        Add a new credential to the cache, or update an existing one.
        """
        result = self._coll.replace_one({'_id': credential._id}, credential.to_dict(), upsert=True)
        logger.debug(f'Updated credential {credential} in the db: {result}')
        return None

    def get_credential(self, credential_id: str) -> Optional[Credential]:
        """
        Lookup an credential using the credential id.

        :param credential_id: Unique credential identifier as string
        :return: The credential, if found
        """
        try:
            res = self._coll.find_one({'credential.credential_id': credential_id})
        except KeyError:
            logger.debug(f'Failed looking up credential with credential_id={repr(credential_id)}')
            raise
        if not res:
            return None
        return Credential.from_dict(res)
