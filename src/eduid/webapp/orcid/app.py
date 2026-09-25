from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.clients.oidc_client import OidcRpClient, init_oidc_rp_client
from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing import OrcidProofingUserDB
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.orcid.helpers import SessionOidcCache
from eduid.webapp.orcid.settings.common import OrcidConfig


class OrcidApp(AuthnBaseApp):
    conf: OrcidConfig

    def __init__(self, config: OrcidConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        # Init dbs
        self.private_userdb = OrcidProofingUserDB(config.mongo_uri, auto_expire=config.private_userdb_auto_expire)
        self.proofing_log = ProofingLog(config.mongo_uri)

        # Init celery
        self.am_relay = AmRelay(config)

        # Initialize the oidc_client
        self.oidc_client: OidcRpClient = init_oidc_rp_client(
            app=self, name="orcid", config=self.conf.orcid_client, cache=SessionOidcCache()
        )


current_orcid_app: OrcidApp = cast(OrcidApp, current_app)


def init_orcid_app(name: str = "orcid", test_config: Mapping[str, Any] | None = None) -> OrcidApp:
    config = load_config(typ=OrcidConfig, app_name=name, ns="webapp", test_config=test_config)

    # Load acs actions on app init
    from . import callback_actions  # noqa: F401

    app = OrcidApp(config)

    app.logger.info(f"Init {name} app...")

    # Register views
    from eduid.webapp.orcid.views import orcid_views

    app.register_blueprint(orcid_views)

    app.logger.info(f"{name!s} initialized")
    return app
