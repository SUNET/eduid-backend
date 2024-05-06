from datetime import datetime
from enum import Enum

from eduid.userdb.db.base import TUserDbDocument
from eduid.userdb.user import User
from eduid.userdb.userdb import UserDB


class CleanerType(str, Enum):
    SKV = "Skatteverket"


class CleanerQueueUser(User):
    """
    User version to bookkeep cleaning actions.
    eppn
    cleaner_type
    next_check_ts
    """

    cleaner_type: CleanerType


class CleanerQueueDB(UserDB[CleanerQueueUser]):
    def __init__(self, db_uri: str, db_name: str = "eduid_user_cleaner", collection: str = "cleaner_queue"):
        super().__init__(db_uri, db_name)

        indexes = {
            "eppn-index-v1": {"key": [("eduPersonPrincipalName", 1)], "unique": True},
        }
        self.setup_indexes(indexes)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> CleanerQueueUser:
        return super().user_from_dict(data)
