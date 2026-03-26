import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from eduid.userdb.testing import MongoTemporaryInstance
from eduid.userdb.user_cleaner.db import CleanerQueueDB


class BaseDBTestCase:
    """
    Base test case that sets up a temporary database for testing.
    """

    @pytest.fixture(autouse=True)
    def setup_db(self) -> None:
        self.mongodb_instance = MongoTemporaryInstance.get_instance()
        self.mongo_uri = self.mongodb_instance.uri


class CleanerQueueTestCase(BaseDBTestCase):
    """
    Base class for tests of the cleaner queue.
    """

    @pytest.fixture(autouse=True)
    def setup_cleaner(self, setup_db: None) -> Iterator[None]:
        if "EDUID_CONFIG_YAML" not in os.environ:
            os.environ["EDUID_CONFIG_YAML"] = "YAML_CONFIG_NOT_USED"

        self.datadir = str(Path(__file__).parent / "tests/data")
        self.cleaner_queue_db = CleanerQueueDB(db_uri=self.mongo_uri)

        yield

        if self.cleaner_queue_db:
            self.cleaner_queue_db._drop_whole_collection()
