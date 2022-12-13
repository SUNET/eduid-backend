import logging
import signal
import os
from abc import ABC

from queue import Queue
import time

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
    """
    All workers base class, for collective functionality
    """

    def __init__(self, cleaner_type: str, test_config: Optional[Dict] = None):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

        self.config = load_config(typ=UserCleanerConfig, app_name="user_cleaner", ns="worker", test_config=test_config)
        super().__init__()

        # stats
        self.stats = init_app_stats(self.config)
        self.stats.count(name="user_cleaner_stats")

        # logging
        self.logger = logging.getLogger(name=cleaner_type)
        init_logging(config=self.config)
        self.logger.info(f"initialize worker {cleaner_type}")

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

        self.logger.info(f"Starting worker {cleaner_type}")

    def exit_gracefully(self, sig, frame) -> None:
        # set variable shutdown_now to True when triggered of SIGTERM or SIGINT
        self.logger.info(f"Received signal: {sig}, shutting down...")
        self.shutdown_now = True

    def _is_quota_reached(self) -> bool:
        # return true if change quota is reached, else false
        # used to prevent a change function to exceed its indented change quota (minimize damage)
        if self.made_changes == 0:
            return False
        self.logger.debug(f"is_quota_reached:: made_changes: {self.made_changes}, max_changes: {self.max_changes}")
        return self.made_changes >= self.max_changes

    def _add_to_made_changes(self) -> None:
        # helper to add to made_changes when a change has happened.
        self.made_changes += 1

    def _populate_max_changes(self) -> None:
        # helper to calculate the maximum allowed changes
        self.logger.debug(
            f"populate_max_changes:: queue_actual_size: {self.queue_actual_size}, change_quota: {self.made_changes}"
        )
        self.max_changes = self.queue_actual_size * self.config.change_quota

    def _make_unhealthy(self) -> None:
        # make Docker health status to unhealthy
        if os.path.exists(self.healthy_path):
            os.remove(self.healthy_path)

    def _make_healthy(self) -> None:
        # make Docker health status to healthy
        Path(self.healthy_path).touch()

    def _sleep(self, milliseconds: int) -> None:
        # sleeps, but respects self.shutdown_now variable,
        # then we do not need to wait for the sleep to finish in order to kill this app.
        for i in range(0, milliseconds, 1):
            if self.shutdown_now:
                return
            time.sleep(1 / milliseconds)

    def enqueuing(self, cleaning_type: CleanerType, identity_type: IdentityType, limit: int):
        # add User objects to queue for further processing
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
