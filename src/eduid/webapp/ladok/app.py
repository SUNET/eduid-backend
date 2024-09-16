from collections.abc import Mapping
from typing import Any, Optional, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing.db import LadokProofingUserDB
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.ladok.client import LadokClient
from eduid.webapp.ladok.settings.common import LadokConfig

__author__ = "lundberg"


class LadokApp(AuthnBaseApp):
    def __init__(self, config: LadokConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.conf = config

        # Init dbs
        self.private_userdb = LadokProofingUserDB(config.mongo_uri)
        self.proofing_log = ProofingLog(config.mongo_uri)

        # Init celery
        self.am_relay = AmRelay(config)

        # Init Ladok client
        self.ladok_client = LadokClient(config=self.conf.ladok_client, env=self.conf.environment)


current_ladok_app: LadokApp = cast(LadokApp, current_app)


def init_ladok_app(name: str = "ladok", test_config: Optional[Mapping[str, Any]] = None) -> LadokApp:
    """
    Create an instance of an ladok app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=LadokConfig, app_name=name, ns="webapp", test_config=test_config)

    app = LadokApp(config)

    app.logger.info(f"Init {app}...")

    # Register views
    from eduid.webapp.ladok.views import ladok_views

    app.register_blueprint(ladok_views)

    return app
