from datetime import datetime
from typing import List

from pydantic import validator

from eduid.userdb.db import TUserDbDocument
from eduid.userdb.element import UserDBValueError
from eduid.userdb.user import User
from eduid.userdb.userdb import UserDB


class ManagedAccount(User):
    """
    Subclass of eduid.userdb.User for managed accounts.
    """

    data_owner: str
    expire_at: datetime

    @validator("eppn", pre=True)
    def check_eppn(cls, v: str) -> str:
        if len(v) != 11 or not v.startswith("ma-"):
            raise UserDBValueError(f"Invalid eppn: {v}")
        return v


class ManagedAccountDB(UserDB[ManagedAccount]):
    def __init__(self, db_uri: str, db_name: str = "eduid_managed_accounts", collection: str = "users"):
        super().__init__(db_uri, db_name, collection)

        indexes = {
            "eppn-index-v1": {"key": [("eduPersonPrincipalName", 1)], "unique": True},
            "expire_at-index-v1": {"key": [("expire_at", 1)], "expireAfterSeconds": 0},
        }
        self.setup_indexes(indexes)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> ManagedAccount:
        return ManagedAccount.from_dict(data)

    def get_users(self, data_owner: str) -> List[ManagedAccount]:
        """
        :return: A list of users with the given organization
        """
        users = self._get_documents_by_aggregate({"data_owner": data_owner, "terminated": {"$exists": False}})
        return self._users_from_documents(users)
