import logging
from typing import List, Optional

from pydantic import validator

from eduid.userdb.db import TUserDbDocument
from eduid.userdb.element import UserDBValueError
from eduid.userdb.exceptions import EduIDDBError
from eduid.userdb.idp import IdPUser
from eduid.userdb.user import User
from eduid.userdb.userdb import UserDB

logger = logging.getLogger(__name__)


class ManagedAccount(User):
    """
    Subclass of eduid.userdb.User for managed accounts.
    """

    @validator("eppn", pre=True)
    def check_eppn(cls, v: str) -> str:
        if len(v) != 11 or not v.startswith("ma-"):
            raise UserDBValueError(f"Invalid eppn: {v}")
        return v


class ManagedAccountDB(UserDB[ManagedAccount]):
    def __init__(self, db_uri: str, db_name: str = "eduid_managed_accounts", collection: str = "users"):
        super().__init__(db_uri, db_name, collection)

        # TODO: Add indexes?

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> ManagedAccount:
        return ManagedAccount.from_dict(data)

    def get_users_by_organization(self, organization: str) -> List[ManagedAccount]:
        """
        :param organization: The organization to search for
        :return: A list of users with the given organization
        """
        # TODO: check for organization
        users = self._get_documents_by_aggregate({"terminated": {"$exists": False}})
        return self._users_from_documents(users)

    def get_account_as_idp_user(self, username: str) -> Optional[IdPUser]:
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
            logger.exception(f"Managed account lookup using {repr(username)} did not return a valid account")
            return None

        if managed_account is None:
            logger.info(f"Unknown managed account: {repr(username)}")
            return None

        logger.debug(f"Found managed account  {managed_account} using {repr(username)}")
        managed_account_dict = managed_account.to_dict()
        managed_account_dict["is_managed_account"] = True
        return IdPUser.from_dict(managed_account_dict)
