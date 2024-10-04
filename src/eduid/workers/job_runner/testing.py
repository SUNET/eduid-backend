import os
import unittest

import pkg_resources

from eduid.userdb.testing import MongoTemporaryInstance
from eduid.userdb.user_cleaner.db import CleanerQueueDB


class BaseDBTestCase(unittest.TestCase):
    """
    Base test case that sets up a temporary database for testing.
    """

    mongodb_instance: MongoTemporaryInstance
    mongo_uri: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.mongodb_instance = MongoTemporaryInstance.get_instance()
        cls.mongo_uri = cls.mongodb_instance.uri


class CleanerQueueTestCase(BaseDBTestCase):
    """
    Base class for tests of the cleaner queue.
    """

    @classmethod
    def setUpClass(cls) -> None:
        return super().setUpClass()

    def setUp(self) -> None:
        if "EDUID_CONFIG_YAML" not in os.environ:
            os.environ["EDUID_CONFIG_YAML"] = "YAML_CONFIG_NOT_USED"

        self.datadir = pkg_resources.resource_filename(__name__, "tests/data")

        self.cleaner_queue_db = CleanerQueueDB(db_uri=self.mongo_uri)

    def tearDown(self) -> None:
        super().tearDown()
        if self.cleaner_queue_db:
            self.cleaner_queue_db._drop_whole_collection()
