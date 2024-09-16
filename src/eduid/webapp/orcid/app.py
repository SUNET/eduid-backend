from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing import OrcidProofingStateDB, OrcidProofingUserDB
from eduid.webapp.common.api import oidc
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.orcid.settings.common import OrcidConfig

__author__ = "lundberg"


class OrcidApp(AuthnBaseApp):
    def __init__(self, config: OrcidConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.conf = config

        # Init dbs
        self.private_userdb = OrcidProofingUserDB(config.mongo_uri)
        self.proofing_statedb = OrcidProofingStateDB(config.mongo_uri)
        self.proofing_log = ProofingLog(config.mongo_uri)

        # Init celery
        self.am_relay = AmRelay(config)

        # Initialize the oidc_client
        self.oidc_client = oidc.init_client(config.client_registration_info, config.provider_configuration_info)


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
