import logging
import signal
from abc import ABC

from queue import Queue

from typing import Optional, Dict

from eduid.common.clients.amapi_client.amapi_client import AMAPIClient
from eduid.common.config.parsers import load_config
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb import AmDB
from eduid.userdb.identity import IdentityType
from eduid.userdb.meta import CleanerType
from eduid.common.logging import init_logging

from eduid.workers.user_cleaner.config import UserCleanerConfig


class WorkerBase(ABC):
    def __init__(self, cleaner_type: CleanerType, test_config: Optional[Dict] = None):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

        self.worker_name = str(cleaner_type.value)

        self.config = load_config(typ=UserCleanerConfig, app_name="user_cleaner", ns="worker", test_config=test_config)
        super().__init__()
        self.logger = logging.getLogger(name=self.worker_name)
        init_logging(config=self.config)
        self.logger.info(f"initialize worker {self.worker_name}")
        self.db = AmDB(db_uri=self.config.mongo_uri)

        self.shutdown_now = False

        self.user_count = self.config.user_count

        self.queue = Queue(maxsize=self.user_count)

        self.made_changes = 0
        self.max_changes = 0

        self.msg_relay = MsgRelay(self.config)

        self.amapi_client = AMAPIClient(
            amapi_url=self.config.amapi.url,
            auth_data=self.config.gnap_auth_data,
        )

        self.logger.info(f"starting worker {cleaner_type.value}")

    def exit_gracefully(self, sig, frame) -> None:
        self.logger.info(f"Recevied signal: {sig}, shutting down...")
        self.shutdown_now = True

    def _is_quota_reached(self) -> bool:
        if self.made_changes == 0:
            return False
        return self.made_changes == self.config.change_quota

    def _add_to_made_changes(self) -> None:
        self.made_changes += 1

    def _populate_max_changes(self):
        self.db.db_count()

    def enqueuing(self, cleaning_type: CleanerType, identity_type: IdentityType, limit: int):
        self.logger.info("Enquing users")
        users = self.db.get_uncleaned_verified_users(
            cleaned_type=cleaning_type,
            identity_type=identity_type,
            limit=limit,
        )
        if len(users) < 1:
            self.logger.warning(f"No users where enqueued")
            return
        for user in users:
            self.logger.info(f"adding: {user.eppn}")
            self.queue.put(user)
