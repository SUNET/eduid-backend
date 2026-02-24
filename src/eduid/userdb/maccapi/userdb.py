import logging
from datetime import datetime

from pydantic import field_validator

from eduid.userdb.db import TUserDbDocument
from eduid.userdb.element import UserDBValueError
from eduid.userdb.exceptions import EduIDDBError
from eduid.userdb.idp import IdPUser
from eduid.userdb.user import User
from eduid.userdb.userdb import UserDB

logger = logging.getLogger(__name__)

EPPN_LENGTH = 11


class ManagedAccount(User):
    """
    Subclass of eduid.userdb.User for managed accounts.
    """

    data_owner: str
    expire_at: datetime

    @field_validator("eppn", mode="before")
    @classmethod
    def check_eppn(cls, v: str) -> str:
        if len(v) != EPPN_LENGTH or not v.startswith("ma-"):
            raise UserDBValueError(f"Invalid eppn: {v}")
        return v

    def to_idp_user(self) -> IdPUser:
        managed_account_dict = self.to_dict()
        # Remove fields that are not part of the IdPUser model
        del managed_account_dict["data_owner"]
        del managed_account_dict["expire_at"]
        # Add is_managed_account field to the IdPUser
        # This is used in the IdPs to distinguish between managed and regular accounts
        managed_account_dict["is_managed_account"] = True
        return IdPUser.from_dict(managed_account_dict)


class ManagedAccountDB(UserDB[ManagedAccount]):
    def __init__(self, db_uri: str, db_name: str = "eduid_managed_accounts", collection: str = "users") -> None:
        super().__init__(db_uri, db_name, collection)

        indexes = {
            "eppn-index-v1": {"key": [("eduPersonPrincipalName", 1)], "unique": True},
            "expire_at-index-v1": {"key": [("expire_at", 1)], "expireAfterSeconds": 0},
        }
        self.setup_indexes(indexes)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> ManagedAccount:
        return ManagedAccount.from_dict(data)

    def get_users(self, data_owner: str) -> list[ManagedAccount]:
        """
        :return: A list of users with the given organization
        """
        users = self._get_documents_by_aggregate({"data_owner": data_owner, "terminated": {"$exists": False}})
        return self._users_from_documents(users)

    def get_account_as_idp_user(self, username: str) -> IdPUser | None:
        """
        Get ManagedAccount from the db
        """
        # username should always start with ma- and be lowercase
        username = username.lower()
        if not username.startswith("ma-"):
            return None

        try:
            if "@" in username:
                # strip scope if present
                username = username.split("@")[0]
            managed_account = self.get_user_by_eppn(username)
        except EduIDDBError:
            logger.exception(f"Managed account lookup using {username!r} did not return a valid account")
            return None

        if managed_account is None:
            logger.info(f"Unknown managed account: {username!r}")
            return None

        logger.debug(f"Found managed account  {managed_account} using {username!r}")
        return managed_account.to_idp_user()
