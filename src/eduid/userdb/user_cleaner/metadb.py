import logging
from typing import Union

from eduid.userdb.db import BaseDB
from eduid.userdb.meta import CleanerType
from eduid.userdb.user_cleaner.meta import Meta

logger = logging.getLogger(__name__)


class MetaDB(BaseDB):
    """Database class for the meta database."""

    def __init__(self, db_uri: str, collection: str = "meta", db_name: str = "eduid_user_cleaner"):
        super().__init__(db_uri, db_name, collection)
        indexes = {"unique-eppn": {"key": [("worker_name", 1)], "unique": True}}

        self.setup_indexes(indexes)

    def save(self, doc: Meta) -> bool:
        """Save och replace an existing meta document."""
        try:
            res = self._coll.replace_one({"cleaner_type": doc.cleaner_type}, doc.to_dict(), upsert=True)
            return res.acknowledged
        except Exception as e:
            logger.error(f"Failed to save meta document: {e}")
            return False

    def get(self, cleaner_type: CleanerType) -> Union[Meta, None]:
        """Get a worker meta from Meta."""
        res = self._coll.find_one({"cleaner_type": cleaner_type})
        if res is None:
            return None
        return Meta.from_dict(data=res)

    def exists(self, cleaner_type: CleanerType) -> bool:
        """Check if a user exists in the cache."""
        return self._coll.count_documents({"cleaner_type": cleaner_type}) > 0
