import asyncio
import logging
import signal

from queue import Queue

from typing import List, Optional, Dict, Union, Any

from eduid.common.config.parsers import load_config
from eduid.userdb import AmDB, User
from eduid.userdb.identity import IdentityType
from eduid.userdb.meta import CleanerType
from eduid.userdb.user import User
from eduid.common.logging import init_logging
from eduid.workers.user_cleaner.utils.skv import consume
from pydantic import BaseModel

from eduid.workers.user_cleaner.config import UserCleanerConfig


class Shutdown:
    shutdown_now = False

    def __init__(self):
        super().__init__()
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self):
        self.shutdown_now = True


class WorkerBase(Shutdown):
    def __init__(self, cleaner_type: CleanerType, test_config: Optional[Dict] = None):
        self.worker_name = str(cleaner_type.value)
        self.config = load_config(typ=UserCleanerConfig, app_name=self.worker_name, ns="api", test_config=test_config)
        super().__init__()
        self.db = AmDB(db_uri=self.config.mongo_uri)

        self.logger = logging.getLogger(name=self.worker_name)
        init_logging(config=self.config)

        self.user_count = self.config.workers[self.worker_name].user_count

        self.queue = Queue(maxsize=self.user_count)

        if test_config:
            self._test_worker_runs = test_config["test_runs"]

        self.logger.info(f"starting worker {cleaner_type}")

    def enqueuing(self, cleaning_type: CleanerType, identity_type: IdentityType, limit: int):
        for user in self.db.get_uncleaned_verified_users(
            cleaned_type=cleaning_type, identity_type=identity_type, limit=limit
        ):
            self.queue.put(user)
            c = self.queue.qsize()
            mura = 1


class SKV(WorkerBase):
    def __init__(self, cleaner_type: CleanerType, test_config: Optional[Dict] = None):
        super().__init__(cleaner_type=cleaner_type.SKV, test_config=test_config)

    def update_name(self, user: User):
        print(user.eppn)

    def run(self):
        test_runs = 0
        while not self.shutdown_now:
            if self._test_worker_runs > 0:
                if self._test_worker_runs <= test_runs:
                    self.shutdown_now = True
                test_runs += 1

            if self.queue.empty():
                self.enqueuing(
                    cleaning_type=CleanerType.SKV,
                    identity_type=IdentityType.NIN,
                    limit=self.config.workers["skv"].user_count,
                )
            user = self.queue.get()

            self.update_name(user=user)

            self.queue.task_done()
            c = self.queue.qsize()
            mura = 1


def init_skv(test_config: Optional[Dict] = None) -> SKV:
    worker = SKV(cleaner_type=CleanerType.SKV, test_config=test_config)
    return worker


if __name__ == "__main__":
    skv = init_skv()
    skv.run()
