from unittest import TestCase

from eduid.userdb.testing import MongoTemporaryInstance
from eduid.userdb.user_cleaner.cachedb import CacheDB
from eduid.userdb.user_cleaner.cache import CacheUser


class TestUserCleanerCache(TestCase):
    def setUp(self):
        self.tmp_db = MongoTemporaryInstance.get_instance()
        self.user_cleaner_meta_db = CacheDB(db_uri=self.tmp_db.uri, collection="skv_cache")

    def tearDown(self):
        self.user_cleaner_meta_db._drop_whole_collection()
