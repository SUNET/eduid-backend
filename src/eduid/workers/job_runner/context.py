import logging
from os import environ

from eduid.common.fastapi.log import init_logging
from eduid.userdb.user_cleaner.db import CleanerQueueDB
from eduid.userdb.userdb import AmDB
from eduid.workers.job_runner.config import JobRunnerConfig


class Context:
    def __init__(self, config: JobRunnerConfig):
        self.name = config.app_name
        self.config = config

        worker_name = environ.get("WORKER_NAME", None)
        if worker_name is None:
            raise RuntimeError("Environment variable WORKER_NAME needs to be set")
        self.worker_name = worker_name

        # Setup logging
        init_logging(self.name, self.config)
        self.logger = logging.getLogger("user_cleaner")
        self.logger.info("Logging initialized")

        # Setup databases
        self.db = AmDB(db_uri=self.config.mongo_uri)
        self.logger.info(f"Database {self.db} initialized")

        self.cleaner_queue = CleanerQueueDB(db_uri=self.config.mongo_uri)
        self.logger.info(f"Database {self.cleaner_queue} initialized")
