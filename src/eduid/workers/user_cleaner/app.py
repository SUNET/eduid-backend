import logging
import signal

from typing import List, Optional, Dict

from eduid.common.config.parsers import load_config
from eduid.userdb import AmDB
from eduid.userdb.meta import CleanedType
from eduid.userdb.user import User
from eduid.common.logging import init_logging
from pydantic import BaseModel

from eduid.workers.user_cleaner.config import UserCleanerConfig


class Shutdown:
    now = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self):
        self.now = True


class Cleaner(Shutdown):
    users: Optional[List[User]] = None

    def __init__(self, name: str = "user_cleaner", test_config: Optional[Dict] = None):
        self.config = load_config(typ=UserCleanerConfig, app_name=name, ns="api", test_config=test_config)
        super().__init__()
        self.name = name

        self.db = AmDB(db_uri=self.config.mongo_uri)

        self.logger = logging.getLogger(name=name)
        init_logging(config=self.config)
        self.logger.info(f"Starting {name} app")

    def __iter__(self):
        return iter(self.users)

    def __getitem__(self, item):
        return self.users[item]

    def fetch_users(self, cleaning_type: CleanedType, limit: int):
        self.users = self.db.get_uncleaned_users(cleaned_type=cleaning_type, limit=limit)

    def run_skv(self):
        self.fetch_users(CleanedType.SKV, 1)
        print("Hej")


def init_app(name: str = "user_cleaner", test_config: Optional[Dict] = None) -> Cleaner:
    app = Cleaner(name=name, test_config=test_config)

    app.logger.info("app running...")
    return app


if __name__ == "__main__":
    app_skv = init_app()
    app_skv.run_skv()
