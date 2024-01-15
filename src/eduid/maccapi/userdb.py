from eduid.userdb.userdb import UserDB
from eduid.maccapi.model.user import ManagedAccount
from eduid.userdb.db import TUserDbDocument
from typing import List

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
        users = self._get_documents_by_aggregate({"terminated" : {"$exists" : False}})
        return self._users_from_documents(users)