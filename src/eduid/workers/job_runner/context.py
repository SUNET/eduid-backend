import logging
from os import environ

from eduid.common.clients.amapi_client.amapi_client import AMAPIClient
from eduid.common.fastapi.log import init_logging
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb.user_cleaner.db import CleanerQueueDB
from eduid.userdb.user_cleaner.userdb import CleanerUserDB
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

        self.private_db = CleanerUserDB(db_uri=self.config.mongo_uri)
        self.logger.info(f"Database {self.private_db} initialized")

        # Setup MsgRelay
        self.msg_relay = MsgRelay(self.config)
        self.logger.info(f"MsgRelay {self.msg_relay} initialized")

        # Setup AmRelay
        self.am_relay = AmRelay(self.config)
        self.logger.info(f"AmRelay {self.am_relay} initialized")

        # Setup amapi client
        self.amapi_client = AMAPIClient(
            amapi_url=self.config.amapi.url,
            auth_data=self.config.gnap_auth_data,
            verify_tls=self.config.amapi.tls_verify,
        )
        self.logger.info(f"AMAPIClient {self.amapi_client} initialized")
