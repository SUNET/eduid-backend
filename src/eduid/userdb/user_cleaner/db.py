import logging

import pymongo

from eduid.userdb.db.base import TUserDbDocument
from eduid.userdb.meta import CleanerType
from eduid.userdb.user import User
from eduid.userdb.userdb import UserDB

logger = logging.getLogger(__name__)


class CleanerQueueUser(User):
    """
    User version to bookkeep cleaning actions.
    eppn
    cleaner_type
    """

    cleaner_type: CleanerType


class CleanerQueueDB(UserDB[CleanerQueueUser]):
    def __init__(self, db_uri: str, db_name: str = "eduid_user_cleaner", collection: str = "cleaner_queue"):
        super().__init__(db_uri, db_name, collection)

        indexes = {
            "eppn-index-v1": {"key": [("eduPersonPrincipalName", 1)], "unique": True},
            "creation-index-v1": {"key": [("meta.created_ts", 1)], "unique": False},
        }
        self.setup_indexes(indexes)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> CleanerQueueUser:
        return CleanerQueueUser.from_dict(data)

    def get_next_user(self, cleaner_type: CleanerType) -> CleanerQueueUser | None:
        doc = self._coll.find_one_and_delete(
            filter={"cleaner_type": cleaner_type}, sort=[("meta.created_ts", pymongo.ASCENDING)]
        )
        if doc is not None:
            logger.debug("Found document")
            user = self.user_from_dict(doc)
            return user
        else:
            logger.debug("No document found")
            return None
