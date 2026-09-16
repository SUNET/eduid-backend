from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.clients.oidc_client import OidcRpClient, init_oidc_rp_client
from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing.db import FrejaEIDProofingUserDB
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.common.authn.utils import no_authn_views
from eduid.webapp.freja_eid.helpers import SessionOidcCache
from eduid.webapp.freja_eid.settings.common import FrejaEIDConfig

__author__ = "lundberg"


class FrejaEIDApp(AuthnBaseApp):
    conf: FrejaEIDConfig

    def __init__(self, config: FrejaEIDConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        # Init dbs
        self.private_userdb = FrejaEIDProofingUserDB(self.conf.mongo_uri, auto_expire=config.private_userdb_auto_expire)
        self.proofing_log = ProofingLog(config.mongo_uri)
        # Init celery
        self.am_relay = AmRelay(config)
        self.msg_relay = MsgRelay(config)

        # Initialize the oidc_client
        self.oidc_client: OidcRpClient = init_oidc_rp_client(
            app=self, name="freja_eid", config=self.conf.freja_eid_client, cache=SessionOidcCache()
        )


current_freja_eid_app = cast(FrejaEIDApp, current_app)


def freja_eid_init_app(name: str = "freja_eid", test_config: Mapping[str, Any] | None = None) -> FrejaEIDApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config. Used in test cases.

    :return: the flask app
    """
    config = load_config(typ=FrejaEIDConfig, app_name=name, ns="webapp", test_config=test_config)

    # Load acs actions on app init
    from . import callback_actions  # noqa: F401

    app = FrejaEIDApp(config)

    app.logger.info(f"Init {app}...")

    # Register views
    from eduid.webapp.freja_eid.views import freja_eid_views

    app.register_blueprint(freja_eid_views)

    # Register view path that should not be authorized
    no_authn_views(
        config,
        ["/mfa-authenticate", "/mfa-register", "/get-status", "/authn-callback"],
    )

    app.logger.info(f"{name!s} initialized")
    return app
