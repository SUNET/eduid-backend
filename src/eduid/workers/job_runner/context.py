import logging
from os import environ

from eduid.common.fastapi.log import init_logging
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb.user_cleaner.db import CleanerQueueDB
from eduid.userdb.user_cleaner.userdb import CleanerUserDB
from eduid.userdb.userdb import AmDB
from eduid.workers.job_runner.config import JobRunnerConfig


class Context:
    def __init__(self, config: JobRunnerConfig) -> None:
        self.name = config.app_name
        self.config = config
        self.dry_run = config.dry_run

        worker_name = environ.get("WORKER_NAME", None)
        if worker_name is None:
            raise RuntimeError("Environment variable WORKER_NAME needs to be set")
        self.worker_name = worker_name

        # Setup logging
        init_logging(self.name, self.config)
        self.logger = logging.getLogger("user_cleaner")
        self.logger.info("Logging initialized")

        # Setup databases
        self.central_db = AmDB(db_uri=self.config.mongo_uri)
        self.logger.info(f"Database {self.central_db} initialized")

        self.cleaner_queue = CleanerQueueDB(db_uri=self.config.mongo_uri)
        self.logger.info(f"Database {self.cleaner_queue} initialized")

        self.private_db = CleanerUserDB(db_uri=self.config.mongo_uri)
        self.logger.info(f"Database {self.private_db} initialized")

        # Setup MsgRelay
        self.msg_relay = MsgRelay(self.config)
        self.logger.info(f"MsgRelay {self.msg_relay} initialized")

        # Setup AmRelay
        self.am_relay = AmRelay(self.config)
        self.logger.info(f"AmRelay {self.am_relay} initialized")
