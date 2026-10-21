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
    def __init__(self, db_uri: str, db_name: str = "eduid_job_runner", collection: str = "cleaner_queue") -> None:
        super().__init__(db_uri, db_name, collection)

        # The same eppn may be queued once per cleaner type (e.g. both SKV and IDENTITY_AGE), so uniqueness is
        # per (eppn, cleaner_type). setup_indexes drops indexes not listed here, so the old eppn-only unique
        # index "eppn-index-v1" is removed automatically on startup.
        indexes = {
            "eppn-cleaner-type-index-v1": {
                "key": [("eduPersonPrincipalName", 1), ("cleaner_type", 1)],
                "unique": True,
            },
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

    def user_in_queue(self, cleaner_type: CleanerType, eppn: str) -> bool:
        return self.db_count(spec={"cleaner_type": cleaner_type, "eduPersonPrincipalName": eppn}, limit=1) > 0
