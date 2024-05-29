import logging
from datetime import datetime
from enum import Enum
from typing import Optional

import pymongo

from eduid.userdb.db.base import TUserDbDocument
from eduid.userdb.identity import IdentityType
from eduid.userdb.meta import CleanerType
from eduid.userdb.user import User
from eduid.userdb.userdb import UserDB, UserVar

logger = logging.getLogger(__name__)


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
        super().__init__(db_uri, db_name, collection)

        indexes = {
            "eppn-index-v1": {"key": [("eduPersonPrincipalName", 1)], "unique": True},
        }
        self.setup_indexes(indexes)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> CleanerQueueUser:
        return CleanerQueueUser.from_dict(data)

    def get_next_user(self) -> Optional[CleanerQueueUser]:
        docs = self._get_documents_by_aggregate(
            match={"cleaner_type": CleanerType.SKV}, sort={"meta.created_ts": pymongo.DESCENDING}, limit=1
        )
        logger.debug(f"Found {len(docs)} documents")
        if len(docs) == 0:
            return None
        else:
            doc = docs[0]
            logger.debug(f"Found document with id {doc['_id']}, removing it from queue")
            user = self.user_from_dict(doc)
            self.remove_document(doc["_id"])
            return user
