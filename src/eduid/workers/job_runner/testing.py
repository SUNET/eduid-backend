import logging
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from eduid.common.stats import AppStats
from eduid.queue.db.message import MessageDB
from eduid.userdb.identity_age.db import IdentityAgeNotificationDB
from eduid.userdb.testing import MongoTemporaryInstance
from eduid.userdb.user_cleaner.db import CleanerQueueDB
from eduid.userdb.userdb import AmDB
from eduid.workers.job_runner.config import JobRunnerConfig
from eduid.workers.job_runner.context import Context


class MockContext(Context):
    """Context stub for tests — skips all real initialisation while passing isinstance checks."""

    def __init__(
        self,
        central_db: AmDB,
        cleaner_queue: CleanerQueueDB,
        logger: logging.Logger,
        config: JobRunnerConfig | None = None,
        messagedb: MessageDB | None = None,
        identity_age_db: IdentityAgeNotificationDB | None = None,
        identity_age_dry_run_db: IdentityAgeNotificationDB | None = None,
        stats: AppStats | None = None,
        dry_run: bool = False,
    ) -> None:
        self.central_db = central_db
        self.cleaner_queue = cleaner_queue
        self.logger = logger
        self.dry_run = dry_run
        if config is not None:
            self.config = config
        if messagedb is not None:
            self.messagedb = messagedb
        if identity_age_db is not None:
            self.identity_age_db = identity_age_db
        if identity_age_dry_run_db is not None:
            self.identity_age_dry_run_db = identity_age_dry_run_db
        if stats is not None:
            self.stats = stats


class BaseDBTestCase:
    """
    Base test case that sets up a temporary database for testing.
    """

    @pytest.fixture(autouse=True)
    def setup_db(self, mongo_instance: MongoTemporaryInstance) -> None:
        self.mongodb_instance = mongo_instance
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
