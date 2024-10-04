import logging

from eduid.common.fastapi.log import init_logging
from eduid.common.stats import init_app_stats
from eduid.maccapi.config import MAccApiConfig
from eduid.maccapi.util import load_jwks
from eduid.userdb.logs.db import ManagedAccountLog
from eduid.userdb.maccapi import ManagedAccountDB
from eduid.vccs.client import VCCSClient


class Context:
    def __init__(self, config: MAccApiConfig, vccs_client: VCCSClient | None = None) -> None:
        self.name = config.app_name
        self.config = config

        # Setup logging
        init_logging(self.name, self.config)
        self.logger = logging.getLogger("eduid_maccapi")
        self.logger.info("Logging initialized")

        # Setup database
        self.db = ManagedAccountDB(config.mongo_uri)
        self.logger.info("Database initialized")

        self.audit_log = ManagedAccountLog(config.mongo_uri)
        self.logger.info("Audit log initialized")

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
