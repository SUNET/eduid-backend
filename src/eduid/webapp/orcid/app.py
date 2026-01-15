from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing import OrcidProofingStateDB, OrcidProofingUserDB
from eduid.webapp.common.api.oidc import init_lazy_client
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.orcid.settings.common import OrcidConfig

__author__ = "lundberg"


class OrcidApp(AuthnBaseApp):
    def __init__(self, config: OrcidConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        # Init dbs
        self.private_userdb = OrcidProofingUserDB(config.mongo_uri, auto_expire=config.private_userdb_auto_expire)
        self.proofing_statedb = OrcidProofingStateDB(config.mongo_uri, auto_expire=config.state_db_auto_expire)
        self.proofing_log = ProofingLog(config.mongo_uri)

        # Init celery
        self.am_relay = AmRelay(config)

        # Init lazy OIDC client with circuit breaker pattern
        self.oidc_client = init_lazy_client(
            client_registration_info=self.conf.client_registration_info,
            provider_configuration_info=self.conf.provider_configuration_info,
        ).client

        self.logger.info("ORCID app initialized with lazy OIDC client loading")


current_orcid_app: OrcidApp = cast(OrcidApp, current_app)


def init_orcid_app(name: str = "orcid", test_config: Mapping[str, Any] | None = None) -> OrcidApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=OrcidConfig, app_name=name, ns="webapp", test_config=test_config)

    app = OrcidApp(config)

    app.logger.info(f"Init {name} app...")

    # Register views
    from eduid.webapp.orcid.views import orcid_views

    app.register_blueprint(orcid_views)

    return app
