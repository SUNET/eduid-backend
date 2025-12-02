from __future__ import annotations

import copy
import logging
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Self

from bson import ObjectId

from eduid.common.misc.timeutil import utc_now
from eduid.userdb import User, UserDB
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.exceptions import DocumentOutOfSync
from eduid.userdb.scimapi.basedb import ScimApiBaseDB
from eduid.userdb.scimapi.common import (
    ScimApiEmail,
    ScimApiLinkedAccount,
    ScimApiName,
    ScimApiPhoneNumber,
    ScimApiProfile,
    ScimApiResourceBase,
)

__author__ = "ft"


logger = logging.getLogger(__name__)


@dataclass
class ScimApiUser(ScimApiResourceBase):
    user_id: ObjectId = field(default_factory=lambda: ObjectId())
    name: ScimApiName = field(default_factory=lambda: ScimApiName())
    emails: list[ScimApiEmail] = field(default_factory=list)
    phone_numbers: list[ScimApiPhoneNumber] = field(default_factory=list)
    preferred_language: str | None = None
    profiles: dict[str, ScimApiProfile] = field(default_factory=dict)
    linked_accounts: list[ScimApiLinkedAccount] = field(default_factory=list)

    @property
    def etag(self) -> str:
        return f'W/"{self.version}"'

    def to_dict(self) -> TUserDbDocument:
        res = asdict(self)
        res["scim_id"] = str(res["scim_id"])
        res["_id"] = res.pop("user_id")
        res["emails"] = [email.to_dict() for email in self.emails]
        res["phone_numbers"] = [phone_number.to_dict() for phone_number in self.phone_numbers]
        res["linked_accounts"] = [acc.to_dict() for acc in self.linked_accounts]
        return TUserDbDocument(res)

    @classmethod
    def from_dict(cls: type[Self], data: Mapping[str, Any]) -> Self:
        this = dict(copy.copy(data))  # to not modify callers data
        this["scim_id"] = uuid.UUID(this["scim_id"])
        this["user_id"] = this.pop("_id")
        # Name
        if this.get("name") is not None:
            this["name"] = ScimApiName.from_dict(this["name"])
        # Emails
        this["emails"] = [ScimApiEmail.from_dict(email) for email in data.get("emails", [])]
        # Phone numbers
        this["phone_numbers"] = [ScimApiPhoneNumber.from_dict(number) for number in data.get("phone_numbers", [])]
        # Profiles
        this["profiles"] = {k: ScimApiProfile.from_dict(v) for k, v in data["profiles"].items()}
        # Linked accounts
        this["linked_accounts"] = [ScimApiLinkedAccount.from_dict(x) for x in data.get("linked_accounts", [])]
        return cls(**this)


class ScimApiUserDB(ScimApiBaseDB):
    def __init__(
        self, db_uri: str, collection: str, db_name: str = "eduid_scimapi", setup_indexes: bool = True
    ) -> None:
        super().__init__(db_uri, db_name, collection=collection)
        if setup_indexes:
            # Create an index so that scim_id and external_id is unique per data owner
            indexes = {
                "unique-scimid": {"key": [("scim_id", 1)], "unique": True},
                "unique-external-id": {
                    "key": [("external_id", 1)],
                    "unique": True,
                    "partialFilterExpression": {"external_id": {"$type": "string"}},
                },
            }
            self.setup_indexes(indexes)

    def save(self, user: ScimApiUser) -> None:
        """
        Save a user to the database.

        TODO: Align these users with the standard UserDB users, using user.meta.version instead.
        """
        user_dict = user.to_dict()

        if "profiles" in user_dict:
            # don't save the special PoC eduid profiles in the database (bson does not allow dots in keys)
            for eduid_domain in ["eduid.se", "dev.eduid.se"]:
                if eduid_domain in user_dict["profiles"]:
                    del user_dict["profiles"][eduid_domain]

        test_doc = {
            "_id": user.user_id,
            "version": user.version,
        }
        # update the version number and last_modified timestamp
        user_dict["version"] = ObjectId()
        user_dict["last_modified"] = utc_now()
        # Save existing user
        result = self._coll.replace_one(test_doc, user_dict, upsert=False)
        if result.modified_count == 0:
            # Could not replace the user, is it new or is something out out sync
            db_user = self._coll.find_one({"_id": user.user_id})
            if db_user:
                logger.debug(f"{self} FAILED Updating user {user} in {self._coll_name}")
                raise DocumentOutOfSync("User out of sync, please retry")
            # Out of sync check did not find any problems, it is a new user - save it.
            _result2 = self._coll.insert_one(user_dict)
        # put the new version number and last_modified in the user object after a successful update
        user.version = user_dict["version"]
        user.last_modified = user_dict["last_modified"]
        logger.debug(f"{self} Updated user {user} in {self._coll_name}")
        import pprint

        extra_debug = pprint.pformat(user_dict, width=120)
        logger.debug(f"Extra debug:\n{extra_debug}")

    def remove(self, user: ScimApiUser) -> bool:
        return self.remove_document(user.user_id)

    def get_user_by_scim_id(self, scim_id: str) -> ScimApiUser | None:
        doc = self._get_document_by_attr("scim_id", scim_id)
        if doc:
            return ScimApiUser.from_dict(doc)
        return None

    def get_user_by_external_id(self, external_id: str) -> ScimApiUser | None:
        doc = self._get_document_by_attr("external_id", external_id)
        if doc:
            return ScimApiUser.from_dict(doc)
        return None

    def get_users_by_last_modified(
        self, operator: str, value: datetime, limit: int | None = None, skip: int | None = None
    ) -> tuple[list[ScimApiUser], int]:
        mongo_operator = self._get_mongo_operator(operator)
        spec = {"last_modified": {mongo_operator: value}}
        docs, total_count = self._get_documents_and_count_by_filter(spec=spec, limit=limit, skip=skip)
        users = [ScimApiUser.from_dict(x) for x in docs]
        return users, total_count

    def get_user_by_profile_data(
        self,
        profile: str,
        key: str,
        operator: str,
        value: str | int,
        limit: int | None = None,
        skip: int | None = None,
    ) -> tuple[list[ScimApiUser], int]:
        mongo_operator = self._get_mongo_operator(operator)
        spec = {f"profiles.{profile}.data.{key}": {mongo_operator: value}}
        docs, total_count = self._get_documents_and_count_by_filter(spec=spec, limit=limit, skip=skip)
        users = [ScimApiUser.from_dict(x) for x in docs]
        return users, total_count

    def user_exists(self, scim_id: str) -> bool:
        return bool(self.db_count(spec={"scim_id": scim_id}, limit=1))


class ScimEduidUserDB(UserDB[User]):
    """EduID userdb"""

    def __init__(self, db_uri: str, db_name: str = "eduid_scimapi") -> None:
        super().__init__(db_uri, db_name)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> User:
        return User.from_dict(data)
