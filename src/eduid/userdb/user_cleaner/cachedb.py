from abc import ABC
from time import time
import logging
from eduid.userdb.db import BaseDB, TUserDbDocument
from eduid.userdb.user import User
from eduid.userdb.user_cleaner.cache import CacheUser

logger = logging.getLogger(__name__)


class CacheDB(BaseDB):
    """Database class for the user cleaning database cache."""

    def __init__(self, db_uri: str, collection: str, db_name: str = "eduid_user_cleaner"):
        super().__init__(db_uri, db_name, collection)
        indexes = {"unique-eppn": {"key": [("eppn", 1)], "unique": True}}

        self.setup_indexes(indexes)

    def save(self, cache_user: CacheUser) -> bool:
        """Save a CacheUser object to the database."""
        if self.exists(cache_user.eppn):
            logger.debug(f"User {cache_user.eppn} already exists in the cache.")
            return False
        self._coll.insert_one(cache_user.to_dict())
        return True

    def exists(self, eppn: str) -> bool:
        """Check if a user exists in the cache."""
        return self.db_count(spec={"eppn": eppn}, limit=1) > 0

    def get_all(self) -> list[CacheUser]:
        """Get all users from the cache."""
        res = self._coll.find({})
        return [CacheUser.from_dict(data=doc) for doc in res]

    def count(self) -> int:
        """Count the number of users in the cache."""
        return self._coll.count_documents({})

    def delete(self, eppn: str) -> None:
        """delete one user from the cache."""
        self._coll.delete_one({"eppn": eppn})

    def delete_all(self) -> None:
        """Delete all users from the cache."""
        self._coll.delete_many({})

    def populate(
        self,
        am_users: list[User],
        periodicity: int,
    ) -> None:
        """Populate cache database with the user from AMDB."""

        cache_size = len(am_users)

        periodicity_in_seconds = 22 * 60 * 60 * periodicity  # strip 2 hours of each day in order to give us some slack
        time_constant = int(periodicity_in_seconds / cache_size)

        next_run_ts = int(time()) + (60 * 60)  # first process window starts in 1 hour, then the population is done
        for am_user in am_users:
            next_run_ts += time_constant
            cache_user = CacheUser(
                eppn=am_user.eppn,
                next_run_ts=next_run_ts,
            )

            self.save(cache_user)

    def is_empty(self) -> bool:
        """Check if the cache is empty."""
        return self.count() == 0
