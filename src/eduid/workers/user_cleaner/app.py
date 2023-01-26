from dataclasses import Field
from datetime import datetime
import logging
import signal
import os
from abc import ABC

from queue import Queue
import time

from typing import Any, Mapping, Optional, Union

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
from eduid.userdb.user_cleaner.cachedb import CacheDB
from eduid.userdb.user_cleaner.cache import CacheUser
from eduid.userdb.user_cleaner.metadb import MetaDB
from eduid.userdb.user_cleaner.meta import Meta


class WorkerBase(ABC):
    """All workers base class, for collective functionality"""

    def __init__(
        self, cleaner_type: CleanerType, identity_type: IdentityType, test_config: Optional[Mapping[str, Any]] = None
    ):
        signal.signal(signal.SIGINT, self._exit_gracefully)
        signal.signal(signal.SIGTERM, self._exit_gracefully)

        self.config = load_config(typ=UserCleanerConfig, app_name="user_cleaner", ns="worker", test_config=test_config)
        super().__init__()

        # stats
        self.stats = init_app_stats(self.config)
        self.stats.count(name="user_cleaner_stats")

        self.cleaner_type = cleaner_type
        self.identity_type = identity_type

        # logging
        self.logger = logging.getLogger(name=self.cleaner_type)
        init_logging(config=self.config)
        self.logger.info(f"initialize worker {self.cleaner_type}")

        self.db = AmDB(db_uri=self.config.mongo_uri)
        self.db_cache: CacheDB
        self.db_meta: MetaDB

        self.shutdown_now = False

        self.worker_queue: "Queue[dict[str, Union[str,int]]]" = Queue(maxsize=0)
        self.queue_actual_size = 0

        self.made_changes = 0
        self.max_changes = 0.0

        self.msg_relay = MsgRelay(self.config)

        self.amapi_client = AMAPIClient(
            amapi_url=self.config.amapi.url,
            auth_data=self.config.gnap_auth_data,
        )

        self.logger.info(f"Starting worker {cleaner_type}")

    def _exit_gracefully(self, sig, frame) -> None:
        """
        Set variable shutdown_now to True when SIGTERM or SIGINT is triggered
        """
        self.logger.info(f"Received signal: {sig}, shutting down...")
        self.shutdown_now = True

    def _is_quota_reached(self) -> bool:
        """
        Return true if change quota is reached, else false.
        Used to prevent a change function to exceed its indented change quota (minimize damage)
        """
        if self.made_changes == 0:
            return False
        self.logger.debug(f"is_quota_reached:: made_changes: {self.made_changes}, max_changes: {self.max_changes}")
        return self.made_changes >= self.max_changes

    def _add_to_made_changes(self) -> None:
        """
        Helper to add to made_changes after a change.
        """
        self.made_changes += 1

    def _populate_max_changes(self) -> None:
        """
        Helper to calculate the maximum allowed changes
        """
        self.logger.debug(
            f"populate_max_changes:: queue_actual_size: {self.queue_actual_size}, change_quota: {self.made_changes}"
        )
        self.max_changes = self.queue_actual_size * self.config.change_quota

    def _make_unhealthy(self) -> None:
        """Make Docker health status to unhealthy"""

        if os.path.exists(self.config.healthy_path):
            os.remove(self.config.healthy_path)

    def _make_healthy(self) -> None:
        """Make Docker health status to healthy"""

        Path(self.config.healthy_path).touch()

    def _sleep(self, seconds: int) -> None:
        """Sleep with an eye on shutdown_now"""
        count = 0
        while count < seconds * 1000:
            count += 1
            if self.shutdown_now:
                self.logger.debug("Shutdown now, exiting sleep")
                return
            time.sleep(0.001)

    def _wait(self, user: CacheUser) -> bool:
        """Wait for user to run at next_run_ts with an eye on shutdown_now"""
        if user.next_run_ts is None:
            self.logger.debug(f"User {user.eppn} has no next_run_ts, skipping wait")
            return False
        self.logger.debug(f"Waiting for user {user.eppn} to run at {user.next_run_ts_iso8601()}")
        while user.next_run_ts > int(time.time()) and not self.shutdown_now:
            if self.shutdown_now:
                return False
            if user.next_run_ts < int(time.time()):
                return True
            time.sleep(0.01)
        return False

    def task_done(self, eppn: str) -> None:
        """Mark a task as done"""
        self.worker_queue.task_done()
        self.db_cache.delete(eppn=eppn)

    def _enqueuing_to_worker_queue(self) -> None:
        """Populate worker queue with cached users"""

        users = self.db_cache.get_all()
        if len(users) == 0:
            self.logger.warning(f"No users where found in cache!")
            return

        for user in users:
            self.worker_queue.put(user.to_dict())
            self.logger.debug(f"enqueuing user: {user.eppn}")

        self.queue_actual_size = self.worker_queue.qsize()
        self._populate_max_changes()

        self.made_changes = 0


def init_worker_base(cleaner_type: CleanerType, identity_type: IdentityType, test_config: dict[str, Any]) -> WorkerBase:
    return WorkerBase(cleaner_type=cleaner_type, identity_type=identity_type, test_config=test_config)
