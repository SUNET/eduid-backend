import logging

from eduid.common.fastapi.log import init_logging
from eduid.maccapi.config import MAccApiConfig
from eduid.maccapi.util import load_jwks
from eduid.userdb.maccapi import ManagedAccountDB


class Context:
    def __init__(self, config: MAccApiConfig):
        self.name = config.app_name
        self.config = config

        # Setup logging
        init_logging(self.name, self.config)
        self.logger = logging.getLogger("eduid_maccapi")
        self.logger.info("Logging initialized")

        # Setup database
        self.db = ManagedAccountDB(config.mongo_uri)
        self.logger.info("Database initialized")

        # Setup keystore
        self.jwks = load_jwks(config)
