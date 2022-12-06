import logging
import signal
import os
from abc import ABC

from queue import Queue

from typing import Optional, Dict

from pathlib import Path

from eduid.common.clients.amapi_client.amapi_client import AMAPIClient
from eduid.common.config.parsers import load_config
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb import AmDB
from eduid.userdb.identity import IdentityType
from eduid.userdb.meta import CleanerType
from eduid.common.logging import init_logging
from eduid.common.stats import init_app_stats

from eduid.workers.user_cleaner.config import UserCleanerConfig


class WorkerBase(ABC):
    def __init__(self, cleaner_type: CleanerType, test_config: Optional[Dict] = None):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

        self.worker_name = str(cleaner_type)

        self.config = load_config(typ=UserCleanerConfig, app_name="user_cleaner", ns="worker", test_config=test_config)
        super().__init__()

        # stats
        self.stats = init_app_stats(self.config)
        self.stats.count(name="user_cleaner_stats")

        # logging
        self.logger = logging.getLogger(name=self.worker_name)
        init_logging(config=self.config)
        self.logger.info(f"initialize worker {self.worker_name}")

        self.db = AmDB(db_uri=self.config.mongo_uri)

        self.shutdown_now = False

        self.queue = Queue(maxsize=self.config.user_count)
        self.queue_actual_size = 0

        self.made_changes = 0
        self.max_changes = 0.0

        self.healthy_path = "/tmp/healthy"

        self.msg_relay = MsgRelay(self.config)

        self.amapi_client = AMAPIClient(
            amapi_url=self.config.amapi.url,
            auth_data=self.config.gnap_auth_data,
        )

        self.logger.info(f"Starting worker {cleaner_type.value}")

    def exit_gracefully(self, sig, frame) -> None:
        self.logger.info(f"Received signal: {sig}, shutting down...")
        self.shutdown_now = True

    def _is_quota_reached(self) -> bool:
        if self.made_changes == 0:
            return False
        self.logger.debug(f"is_quota_reached:: made_changes: {self.made_changes}, max_changes: {self.max_changes}")
        return self.made_changes >= self.max_changes

    def _add_to_made_changes(self) -> None:
        self.made_changes += 1

    def _populate_max_changes(self):
        self.logger.debug(
            f"populate_max_changes:: queue_actual_size: {self.queue_actual_size}, change_quota: {self.made_changes}"
        )
        self.max_changes = self.queue_actual_size * self.config.change_quota


    def _make_unhealthy(self) -> None:
        os.remove(self.healthy_path) if os.path.exists(self.healthy_path) else None

    def _make_healthy(self) -> None:
        Path(self.healthy_path).touch()


    def enqueuing(self, cleaning_type: CleanerType, identity_type: IdentityType, limit: int):
        users = self.db.get_uncleaned_verified_users(
            cleaned_type=cleaning_type,
            identity_type=identity_type,
            limit=limit,
        )
        if len(users) == 0:
            self.logger.warning(f"No users where enqueued")
            return
        for user in users:
            self.queue.put(user)
            self.logger.debug(f"enqueuing user: {user.eppn}")

        self.queue_actual_size = self.queue.qsize()
        self._populate_max_changes()

        self.made_changes = 0
