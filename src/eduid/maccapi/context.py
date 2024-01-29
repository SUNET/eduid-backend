import logging
from typing import Optional

from eduid.common.fastapi.log import init_logging
from eduid.maccapi.config import MAccApiConfig
from eduid.maccapi.util import load_jwks
from eduid.userdb.maccapi import ManagedAccountDB
from eduid.vccs.client import VCCSClient

from eduid.common.stats import init_app_stats

class Context:
    def __init__(self, config: MAccApiConfig, vccs_client: Optional[VCCSClient] = None):
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

        # Setup VCCS client
        if vccs_client:
            self.vccs_client = vccs_client
        else:
            self.vccs_client = VCCSClient(base_url=config.vccs_url)

        # Setup stats
        self.stats = init_app_stats(config=config)
        self.logger.info("Stats initialized")