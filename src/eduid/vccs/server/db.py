from __future__ import annotations

import builtins
from collections.abc import Mapping
from dataclasses import asdict, field
from enum import Enum, StrEnum, unique
from typing import Any, cast

from bson import ObjectId
from loguru import logger
from pydantic import ConfigDict
from pydantic.dataclasses import dataclass
from pymongo.errors import DuplicateKeyError

from eduid.userdb.db import BaseDB, TUserDbDocument


@unique
class Status(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


@unique
class Version(StrEnum):
    NDNv1 = "NDNv1"


@unique
class KDF(StrEnum):
    PBKDF2_HMAC_SHA512 = "PBKDF2-HMAC-SHA512"


class CredType(StrEnum):
    PASSWORD = "password"
    REVOKED = "revoked"


@dataclass(config=ConfigDict(arbitrary_types_allowed=True))
class Credential:
    credential_id: str
    status: Status
    type: CredType
    revision: int = 1
    obj_id: ObjectId = field(default_factory=ObjectId)

    @classmethod
    def _from_dict(cls: builtins.type[Credential], data: Mapping[str, Any]) -> Credential:
        """Construct element from a data dict in database format."""

        _data = dict(data)  # to not modify callers data
        if "credential" in _data:
            # move contents from 'credential' to top-level of dict
            _data.update(_data.pop("credential"))
        if "_id" in _data:
            # Not supported with pydantic dataclasses:
            #   RuntimeWarning: fields may not start with an underscore, ignoring "_id"
            _data["obj_id"] = _data.pop("_id")
        return cls(**_data)

    def to_dict(self) -> TUserDbDocument:
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
        obj_id = data.pop("obj_id")
        revision = data.pop("revision")
        return TUserDbDocument(
            {
                "_id": obj_id,
                "revision": revision,
                "credential": data,
            }
        )


@dataclass(config=ConfigDict(arbitrary_types_allowed=True))
class _PasswordCredentialRequired:
    derived_key: str
    iterations: int
    kdf: KDF
    key_handle: int
    salt: str
    version: Version


@dataclass(config=ConfigDict(arbitrary_types_allowed=True))
class PasswordCredential(Credential, _PasswordCredentialRequired):
    @classmethod
    def from_dict(cls: type[PasswordCredential], data: Mapping[str, Any]) -> PasswordCredential:
        # This indirection provides the correct return type for this subclass
        return cast(PasswordCredential, cls._from_dict(data))


@dataclass
class _RevokedCredentialRequired:
    reason: str
    reference: str


@dataclass(config=ConfigDict(arbitrary_types_allowed=True))
class RevokedCredential(Credential, _RevokedCredentialRequired):
    @classmethod
    def from_dict(cls: type[RevokedCredential], data: Mapping[str, Any]) -> RevokedCredential:
        # This indirection provides the correct return type for this subclass
        return cast(RevokedCredential, cls._from_dict(data))

    @classmethod
    def from_dict_backwards_compat(cls: type[RevokedCredential], data: Mapping[str, Any]) -> RevokedCredential:
        """The old VCCS backend stored revoked credentials like this:

        {
            'status': 'revoked',
            'credential_id': '4712',
            'key_handle': 1,
            'type': 'password',
            'kdf': 'PBKDF2-HMAC-SHA512',
            'derived_key': '599ab85b4539b3475...040ab2df0f',
            'version': 'NDNv1',
            'revocation_info': {
                'timestamp': 1608286347,
                'client_ip': '172.16.10.1',
                'reason': 'Testing',
                'reference': '',
            },
            'iterations': 50000,
            'salt': '6bcd35c5f9d306494cc166a183f3da91',
        }
        """
        _data = dict(data)  # to not modify callers data
        if "credential" in _data:
            # move contents from 'credential' to top-level of dict
            _data.update(_data.pop("credential"))
        if "_id" in _data:
            # Not supported with pydantic dataclasses:
            #   RuntimeWarning: fields may not start with an underscore, ignoring "_id"
            _data["obj_id"] = _data.pop("_id")

        _new_data = {
            "credential_id": _data["credential_id"],
            "reason": _data["revocation_info"]["reason"],
            "reference": _data["revocation_info"]["reference"],
            "status": Status.DISABLED,
            "type": CredType.REVOKED,
        }

        return cls(**_new_data)


class CredentialDB(BaseDB):
    def __init__(self, db_uri: str, db_name: str = "vccs_auth_credstore", collection: str = "credentials") -> None:
        super().__init__(db_uri, db_name, collection=collection)

        indexes = {
            "unique-credential-id": {"key": [("credential.credential_id", 1)], "unique": True},
        }
        self.setup_indexes(indexes)

    def add(self, credential: Credential) -> bool:
        """
        Add a new credential to the database.
        Returns True on success.
        """
        try:
            result = self._coll.insert_one(credential.to_dict())
        except DuplicateKeyError:
            logger.warning(f"A credential with credential_id {credential.credential_id} already exists in the db")
            return False
        _success = result.inserted_id == credential.obj_id
        logger.debug(f"Added credential {credential} to the db: {_success}")
        return _success

    def save(self, credential: Credential) -> bool:
        """
        Update an existing credential in the database.

        Returns True on success.
        """
        # Ensure atomicity in updates
        _revision = credential.revision
        credential.revision += 1
        result = self._coll.replace_one({"_id": credential.obj_id, "revision": _revision}, credential.to_dict())
        if result.modified_count == 1:
            logger.debug(f"Updated credential {credential} in the db (to revision {credential.revision}): {result}")
            return True
        logger.warning(
            f"Could not update credential {credential} (to revision {credential.revision}): {result.raw_result}"
        )
        credential.revision -= 1
        return False

    def get_credential(self, credential_id: str) -> PasswordCredential | RevokedCredential | None:
        """
        Lookup an credential using the credential id.

        :param credential_id: Unique credential identifier as string
        :return: The credential, if found
        """
        try:
            res = self._coll.find_one({"credential.credential_id": credential_id})
        except KeyError:
            logger.debug(f"Failed looking up credential with credential_id={repr(credential_id)}")
            raise
        if not res:
            return None
        if "credential" in res:
            if res["credential"].get("status") == "revoked":
                return RevokedCredential.from_dict_backwards_compat(res)
            _type = res["credential"].get("type")
            if _type == CredType.PASSWORD.value:
                return PasswordCredential.from_dict(res)
            elif _type == CredType.REVOKED.value:
                return RevokedCredential.from_dict(res)
            logger.error(f"Credential {credential_id} has unknown type: {_type}")
        return None
