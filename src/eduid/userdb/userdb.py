import logging
from abc import ABC
from dataclasses import dataclass
from typing import Any, Generic, Mapping, Optional, TypeVar, Union

import pymongo
from bson import ObjectId
from bson.errors import InvalidId
from pymongo import ReturnDocument

from eduid.userdb.db import BaseDB, TUserDbDocument
from eduid.userdb.exceptions import (
    DocumentDoesNotExist,
    DocumentOutOfSync,
    EduIDDBError,
    EduIDUserDBError,
    MultipleDocumentsReturned,
    MultipleUsersReturned,
    UserDoesNotExist,
    UserOutOfSync,
)
from eduid.userdb.identity import IdentityType
from eduid.userdb.meta import Meta
from eduid.userdb.user import User

logger = logging.getLogger(__name__)
extra_debug_logger = logger.getChild("extra_debug")

UserVar = TypeVar("UserVar")


@dataclass
class UserSaveResult:
    success: bool


class UserDB(BaseDB, Generic[UserVar], ABC):
    """
    Interface class to the central eduID UserDB.

    :param db_uri: mongodb:// URI to connect to
    :param db_name: mongodb database name
    :param collection: mongodb collection name
    """

    def __init__(self, db_uri: str, db_name: str, collection: str = "userdb"):
        if db_name == "eduid_am" and collection == "userdb":
            # Hack to get right collection name while the configuration points to the old database
            collection = "attributes"
        self.collection = collection

        super().__init__(db_uri, db_name, collection)

        logger.debug(f"{self} connected to database")

    def __repr__(self):
        return f"<eduID {self.__class__.__name__}: {self._db.sanitized_uri} {repr(self._coll_name)})>"

    __str__ = __repr__

    def _users_from_documents(self, documents: list[TUserDbDocument]) -> list[UserVar]:
        """
        Covert a list of user documents to a list of User instances.

        NOTE: This method flags the users as being present in the database, so NEVER call it on anything
              excepts documents just loaded from the database!!! Doing so will wreck saving the User to the database.

        :param documents: List of user documents
        :return: List of User instances
        """
        res: list[UserVar] = []
        for x in [self.user_from_dict(doc) for doc in documents]:
            # Flag this user as being present in the database
            _meta = getattr(x, "meta", None)
            if isinstance(_meta, Meta):
                _meta.is_in_database = True
            res.append(x)
        return res

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> UserVar:
        # must be implemented by subclass to get correct type information
        raise NotImplementedError(f"user_from_dict not implemented in UserDB subclass {cls}")

    def get_user_by_id(self, user_id: Union[str, ObjectId]) -> Optional[UserVar]:
        """
        Locate a user in the userdb given the user's _id.

        :param user_id: User identifier

        :return: User instance | None
        """
        if not isinstance(user_id, ObjectId):
            try:
                user_id = ObjectId(user_id)
            except InvalidId:
                return None
        return self._get_user_by_attr("_id", user_id)

    def get_verified_users_count(self, identity_type: Optional[IdentityType] = None) -> int:
        spec: dict[str, Any]
        spec = {
            "identities": {
                "$elemMatch": {
                    "verified": True,
                }
            }
        }
        if identity_type is not None:
            spec["identities"]["$elemMatch"]["identity_type"] = identity_type.value
        return self.db_count(spec=spec)

    def _get_user_by_filter(self, filter: Mapping[str, Any]) -> list[UserVar]:
        """
        return the user matching the provided filter.

        :param filter: The filter to match the user

        :return: List of User instances
        """
        try:
            users: list[TUserDbDocument] = list(self._get_documents_by_filter(filter))
        except DocumentDoesNotExist:
            logger.debug(f"{self!s} No user found with filter {filter!r} in {self._coll_name!r}")
            raise UserDoesNotExist(f"No user matching filter {filter!r}")

        return self._users_from_documents(users)

    def get_user_by_mail(self, email: str) -> Optional[UserVar]:
        """Locate a user with a (confirmed) e-mail address"""
        res = self.get_users_by_mail(email=email)
        if not res:
            return None
        if len(res) > 1:
            raise MultipleUsersReturned(f"Multiple matching users for email {repr(email)}")
        return res[0]

    def get_users_by_mail(self, email: str, include_unconfirmed: bool = False) -> list[UserVar]:
        """
        Return the user object in the central eduID UserDB having
        an email address matching 'email'. Unless include_unconfirmed=True, the
        email address has to be confirmed/verified.

        :param email: The email address to look for
        :param include_unconfirmed: Require email address to be confirmed/verified.

        :return: User instance
        """
        email = email.lower()
        elemmatch = {"email": email, "verified": True}
        if include_unconfirmed:
            elemmatch = {"email": email}
        filter = {"$or": [{"mail": email}, {"mailAliases": {"$elemMatch": elemmatch}}]}
        return self._get_user_by_filter(filter)

    def get_user_by_nin(self, nin: str) -> Optional[UserVar]:
        """Locate a user with a (confirmed) NIN"""
        res = self.get_users_by_nin(nin=nin)
        if not res:
            return None
        if len(res) > 1:
            raise MultipleUsersReturned(f"Multiple matching users for NIN {repr(nin)}")
        return res[0]

    def get_users_by_nin(self, nin: str, include_unconfirmed: bool = False) -> list[UserVar]:
        """
        Return the user object in the central eduID UserDB having
        a NIN matching 'nin'. Unless include_unconfirmed=True, the
        NIN has to be confirmed/verified.

        :param nin: The nin to look for
        :param include_unconfirmed: Require nin to be confirmed/verified.

        :return: List of User instances
        """

        match = {"identity_type": IdentityType.NIN.value, "number": nin, "verified": True}
        if include_unconfirmed:
            del match["verified"]
        _filter = {"identities": {"$elemMatch": match}}
        return self._get_user_by_filter(_filter)

    def get_users_by_identity(
        self, identity_type: IdentityType, key: str, value: str, include_unconfirmed: bool = False
    ):
        match = {"identity_type": identity_type.value, key: value, "verified": True}
        if include_unconfirmed:
            del match["verified"]
        _filter = {"identities": {"$elemMatch": match}}
        return self._get_user_by_filter(_filter)

    def get_user_by_phone(self, phone: str) -> Optional[UserVar]:
        """Locate a user with a (confirmed) phone number"""
        res = self.get_users_by_phone(phone=phone)
        if not res:
            return None
        if len(res) > 1:
            raise MultipleUsersReturned(f"Multiple matching users for phone {repr(phone)}")
        return res[0]

    def get_users_by_phone(self, phone: str, include_unconfirmed: bool = False) -> list[UserVar]:
        """
        Return the user object in the central eduID UserDB having
        a phone number matching 'phone'. Unless include_unconfirmed=True, the
        phone number has to be confirmed/verified.

        :param phone: The phone to look for
        :param include_unconfirmed: Require phone to be confirmed/verified.

        :return: List of User instances
        """
        oldmatch = {"mobile": phone, "verified": True}
        if include_unconfirmed:
            oldmatch = {"mobile": phone}
        old_filter = {"mobile": {"$elemMatch": oldmatch}}
        newmatch = {"number": phone, "verified": True}
        if include_unconfirmed:
            newmatch = {"number": phone}
        new_filter = {"phone": {"$elemMatch": newmatch}}
        filter = {"$or": [old_filter, new_filter]}
        return self._get_user_by_filter(filter)

    def get_user_by_eppn(self, eppn: Optional[str]) -> UserVar:
        """
        Look for a user using the eduPersonPrincipalName.

        :param eppn: eduPersonPrincipalName to look for
        """
        # allow eppn=None as convenience, to not have to check it everywhere before calling this function
        if eppn is None:
            raise ValueError("eppn must not be None")
        res = self._get_user_by_attr("eduPersonPrincipalName", eppn)
        if not res:
            raise UserDoesNotExist(f"No user with eppn {repr(eppn)}")
        return res

    def _get_user_by_attr(self, attr: str, value: Any) -> Optional[UserVar]:
        """
        Locate a user in the userdb using any attribute and value.

        This is a private function since callers can't depend on the name of things in the db.

        :param attr: The attribute to match on
        :param value: The value to match on

        :raise self.UserDoesNotExist: No user match the search criteria
        :raise self.MultipleUsersReturned: More than one user matches the search criteria
        """
        user = None
        logger.debug(f"{self!s} Looking in {self._coll_name!r} for user with {attr!r} = {value!r}")
        try:
            doc = self._get_document_by_attr(attr, value)
            if doc is not None:
                logger.debug("{!s} Found user with id {!s}".format(self, doc["_id"]))
                user = self._users_from_documents([doc])[0]
                logger.debug(f"{self!s} Returning user {user!s}")
            return user
        except DocumentDoesNotExist as e:
            logger.debug(f"UserDoesNotExist, {attr!r} = {value!r}")
            raise UserDoesNotExist(e.reason)
        except MultipleDocumentsReturned as e:
            logger.error(f"MultipleUsersReturned, {attr!r} = {value!r}")
            raise MultipleUsersReturned(e.reason)

    def save(self, user: UserVar) -> UserSaveResult:
        """
        :param user: User object
        """
        if not isinstance(user, User):
            raise EduIDUserDBError(f"user is not a subclass of User")

        spec: dict[str, Any] = {"_id": user.user_id}
        try:
            result = self._save(user.to_dict(), spec, is_in_database=user.meta.is_in_database, meta=user.meta)
        except DocumentOutOfSync:
            raise UserOutOfSync("User out of sync")

        user.modified_ts = result.ts

        return UserSaveResult(success=bool(result))

    def remove_user_by_id(self, user_id: ObjectId) -> bool:
        """
        Remove a user in the userdb given the user's _id.

        NOTE: Full removal of a user should never be done in the central userdb. Kantara
        requires guarantees to not re-use user identifiers (eppn and _id in eduid) and
        we implement that by never removing the complete document from the central userdb.

        Some other applications might have legitimate reasons to remove users from their
        private userdb collections though (like eduid-signup, at the end of the signup
        process). And it might be used in tests.

        :param user_id: User id
        """
        logger.debug(f"{self!s} Removing user with id {user_id!r} from {self._coll_name!r}")
        return self.remove_document(spec_or_id=user_id)

    def update_user(self, obj_id: ObjectId, operations: Mapping[str, Any]) -> None:
        """
        Update (or insert) a user document in mongodb.

        operations must be a dict with update operators ({'$set': ..., '$unset': ...}).
        https://docs.mongodb.com/manual/reference/operator/update/

        This update method should only be used in the eduid Attribute Manager when
        merging updates from applications into the central eduID userdb.
        """
        logger.debug(f"{self} updating user {obj_id} in {repr(self._coll_name)} with operations:\n{operations}")

        query_filter = {"_id": obj_id}

        # Check that the operations dict includes only the whitelisted operations
        whitelisted_operations = ["$set", "$unset"]
        bad_operators = [key for key in operations if key not in whitelisted_operations]
        if bad_operators:
            logger.debug(f"Tried to update/insert document: {query_filter} with operations: {operations}")
            error_msg = f"Invalid update operator: {bad_operators}"
            logger.error(error_msg)
            raise EduIDDBError(error_msg)

        updated_doc = self._coll.find_one_and_update(
            filter=query_filter, update=operations, return_document=ReturnDocument.AFTER, upsert=True
        )
        logger.debug(f"Updated/inserted document: {updated_doc}")


class AmDB(UserDB[User]):
    """Central userdb, aka. AM DB"""

    def __init__(self, db_uri: str, db_name: str = "eduid_am"):
        super().__init__(db_uri, db_name)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> User:
        return User.from_dict(data)

    def save(self, user: User) -> UserSaveResult:
        """
        Save a User object to the database.
        """
        spec: dict[str, Any] = {"_id": user.user_id}

        try:
            result = self._save(user.to_dict(), spec, is_in_database=user.meta.is_in_database, meta=user.meta)
        except DocumentOutOfSync:
            raise UserOutOfSync("User out of sync")

        user.modified_ts = result.ts

        return UserSaveResult(success=bool(result))

    def get_unterminated_users_with_nin(self) -> list[User]:
        match = {
            "identities": {
                "$elemMatch": {
                    "verified": True,
                    "identity_type": IdentityType.NIN.value,
                }
            },
            "terminated": {"$exists": False},
        }

        users = self._get_documents_by_aggregate(match=match)
        return self._users_from_documents(users)

    def unverify_mail_aliases(self, user_id: ObjectId, mail_aliases: Optional[list[dict[str, Any]]]) -> int:
        count = 0
        if mail_aliases is None:
            logger.debug(f"No mailAliases to check duplicates against for user {user_id}.")
            return count
        # Get the verified mail addresses from attributes
        verified_mail_aliases = [alias["email"] for alias in mail_aliases if alias.get("verified") is True]
        for email in verified_mail_aliases:
            try:
                for user in self.get_users_by_mail(email):
                    if user.user_id != user_id:
                        logger.debug(f"Removing mail address {email} from user {user}")
                        logger.debug(f"Old user mail aliases BEFORE: {user.mail_addresses.to_list()}")
                        if user.mail_addresses.primary and user.mail_addresses.primary.email == email:
                            # Promote some other verified e-mail address to primary
                            for address in user.mail_addresses.to_list():
                                if address.is_verified and address.email != email:
                                    user.mail_addresses.set_primary(address.key)
                                    break
                        old_user_mail_address = user.mail_addresses.find(email)
                        if old_user_mail_address is not None:
                            old_user_mail_address.is_primary = False
                            old_user_mail_address.is_verified = False
                        count += 1
                        logger.debug(f"Old user mail aliases AFTER: {user.mail_addresses.to_list()}")
                        self.save(user)
            except DocumentDoesNotExist:
                pass
        return count

    def unverify_phones(self, user_id: ObjectId, phones: list[dict[str, Any]]) -> int:
        count = 0
        if phones is None:
            logger.debug(f"No phones to check duplicates against for user {user_id}.")
            return count
        # Get the verified phone numbers from attributes
        verified_phone_numbers = [phone["number"] for phone in phones if phone.get("verified") is True]
        for number in verified_phone_numbers:
            try:
                for user in self.get_users_by_phone(number):
                    if user.user_id != user_id:
                        logger.debug(f"Removing phone number {number} from user {user}")
                        logger.debug(f"Old user phone numbers BEFORE: {user.phone_numbers.to_list()}.")
                        if user.phone_numbers.primary and user.phone_numbers.primary.number == number:
                            # Promote some other verified phone number to primary
                            for phone in user.phone_numbers.verified:
                                if phone.number != number:
                                    user.phone_numbers.set_primary(phone.key)
                                    break
                        old_user_phone_number = user.phone_numbers.find(number)
                        if old_user_phone_number is not None:
                            old_user_phone_number.is_primary = False
                            old_user_phone_number.is_verified = False
                        count += 1
                        logger.debug(f"Old user phone numbers AFTER: {user.phone_numbers.to_list()}.")
                        self.save(user)
            except DocumentDoesNotExist:
                pass
        return count
