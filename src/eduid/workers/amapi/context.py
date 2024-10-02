import logging

from eduid.common.fastapi.log import init_logging
from eduid.userdb import AmDB
from eduid.userdb.logs.db import UserChangeLog
from eduid.workers.amapi.config import AMApiConfig
from eduid.workers.amapi.utils import load_jwks


class Context:
    def __init__(self, config: AMApiConfig) -> None:
        self.name = config.app_name
        self.config = config

        # Setup logging
        init_logging(self.name, self.config)
        self.logger = logging.getLogger("eduid_amapi")
        self.logger.info("Logging initialized")

        # Setup database
        self.db = AmDB(db_uri=self.config.mongo_uri)

        self.audit_logger = UserChangeLog(self.config.mongo_uri)

        self.jwks = load_jwks(self.config)
