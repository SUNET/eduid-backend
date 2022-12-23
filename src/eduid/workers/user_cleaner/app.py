from dataclasses import Field
import logging
import signal
import os
from abc import ABC

from queue import Queue
import time

from typing import Any, List, Optional, Dict
from pydantic import BaseModel

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
from eduid.userdb.user import User


class WorkerBase(ABC):
    """
    All workers base class, for collective functionality
    """

    def __init__(self, cleaner_type: CleanerType, identity_type: IdentityType, test_config: Optional[Dict] = None):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

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

        self.shutdown_now = False

        self.queue: "Queue[dict[str, Any]]" = Queue(maxsize=0)
        self.queue_actual_size = 0

        self.made_changes = 0
        self.max_changes = 0.0

        self.healthy_path = "/tmp/healthy"

        self.msg_relay = MsgRelay(self.config)

        self.amapi_client = AMAPIClient(
            amapi_url=self.config.amapi.url,
            auth_data=self.config.gnap_auth_data,
        )
        self.execution_delay = self.get_delay_time()

        self.logger.info(f"Starting worker {cleaner_type}")

    def exit_gracefully(self, sig, frame) -> None:
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
        """
        Make Docker health status to unhealthy
        """
        if os.path.exists(self.healthy_path):
            os.remove(self.healthy_path)

    def _make_healthy(self) -> None:
        """
        Make Docker health status to healthy
        """
        Path(self.healthy_path).touch()

    def _sleep(self, milliseconds: int) -> None:
        """
        Sleep with an eye on self.shutdown_now variable,
        then we do not need to wait for the complete sleep duration to finish in order to kill this app.
        """
        self.logger.debug(f"Entering sleep cycle {milliseconds}")
        index = 0
        while index != milliseconds:
            index += 1
            if self.shutdown_now:
                return
            time.sleep(0.001)

    def get_delay_time(self) -> int:
        """
        Since a given dataset will differ in size and execution time, a calculated delay time has to be made.
        example: time_to_clean_dataset = 10000 milliseconds, user_count = 10, minimum_delay = 1 milliseconds
        --> 10000 / (10*1) => 1000 milliseconds/user document
        each user document have to sleep for 1000 milliseconds to be done with in time (10000 milliseconds).
        """
        user_count = self.db.get_verified_users_count(identity_type=self.identity_type)
        time_per_user = self.config.time_to_clean_dataset / (user_count * (self.config.minimum_delay + 1))
        if time_per_user < self.config.minimum_delay:
            self.logger.warning(f"execution will be faster then minimum execution time: {self.config.minimum_delay}")
        return int(time_per_user)

    def _populate_queue(self, users: List[User]) -> None:
        """Populate queue with user representation"""

        for user in users:
            queue_object = {
                "eppn": user.eppn,
                "nin": None,
            }
            if user.identities.nin is not None:
                queue_object["nin"] = user.identities.nin.number
            self.queue.put(queue_object)
            self.logger.debug(f"enqueuing user: {user.eppn}")

    def enqueuing(self) -> None:
        """Add users to queue for further processing"""

        users = self.db.get_uncleaned_verified_users(
            cleaned_type=self.cleaner_type,
            identity_type=self.identity_type,
            limit=10000000,
        )
        if len(users) == 0:
            self.logger.warning(f"No users where enqueued")
            return
        self._populate_queue(users=users)

        self.queue_actual_size = self.queue.qsize()
        self._populate_max_changes()

        self.made_changes = 0


def init_worker_base(cleaner_type: CleanerType, identity_type: IdentityType, test_config: dict[str, Any]) -> WorkerBase:
    return WorkerBase(cleaner_type=cleaner_type, identity_type=identity_type, test_config=test_config)
