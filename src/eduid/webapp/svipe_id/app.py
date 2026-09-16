from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.clients.oidc_client import OidcRpClient, init_oidc_rp_client
from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing.db import SvideIDProofingUserDB
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.svipe_id.helpers import SessionOidcCache
from eduid.webapp.svipe_id.settings.common import SvipeIdConfig

__author__ = "lundberg"


class SvipeIdApp(AuthnBaseApp):
    conf: SvipeIdConfig

    def __init__(self, config: SvipeIdConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        # Init dbs
        self.private_userdb = SvideIDProofingUserDB(self.conf.mongo_uri, auto_expire=config.private_userdb_auto_expire)
        self.proofing_log = ProofingLog(config.mongo_uri)
        # Init celery
        self.am_relay = AmRelay(config)

        # Initialize the oidc_client
        self.oidc_client: OidcRpClient = init_oidc_rp_client(
            app=self, name="svipe", config=self.conf.svipe_client, cache=SessionOidcCache()
        )


current_svipe_id_app = cast(SvipeIdApp, current_app)


def svipe_id_init_app(name: str = "svipe_id", test_config: Mapping[str, Any] | None = None) -> SvipeIdApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config. Used in test cases.

    :return: the flask app
    """
    config = load_config(typ=SvipeIdConfig, app_name=name, ns="webapp", test_config=test_config)

    # Load acs actions on app init
    from . import callback_actions  # noqa: F401

    app = SvipeIdApp(config)

    app.logger.info(f"Init {app}...")

    # Register views
    from eduid.webapp.svipe_id.views import svipe_id_views

    app.register_blueprint(svipe_id_views)

    app.logger.info(f"{name!s} initialized")
    return app
