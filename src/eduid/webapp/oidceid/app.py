from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.clients.oidc_client import OidcRpClient, init_oidc_rp_client
from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb.logs.db import ProofingLog
from eduid.userdb.proofing.db import OidcEidProofingUserDB
from eduid.webapp.common.api.utils import get_external_url
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.common.authn.utils import no_authn_views
from eduid.webapp.oidceid.settings.common import OidcEidConfig

__author__ = "lundberg"

CALLBACK_ENDPOINT = "oidceid.authn_callback"


class OidcEidApp(AuthnBaseApp[OidcEidConfig]):
    def __init__(self, config: OidcEidConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        # Init dbs
        self.private_userdb = OidcEidProofingUserDB(config.mongo_uri, auto_expire=config.private_userdb_auto_expire)
        self.proofing_log = ProofingLog(config.mongo_uri)

        # Init celery
        self.am_relay = AmRelay(config)
        self.msg_relay = MsgRelay(config)

        # One OIDC RP client per configured OpenID Provider, keyed by issuer. The clients need the registered
        # callback URL, so they are set up in init_oidceid_app once the views exist.
        self.oidc_clients: dict[str, OidcRpClient] = {}
        # The redirect URI registered at the OPs, the same value for the clients, the start and the callback
        self.redirect_uri: str = ""


current_oidceid_app = cast(OidcEidApp, current_app)


def init_oidceid_app(name: str = "oidceid", test_config: Mapping[str, Any] | None = None) -> OidcEidApp:
    """
    Create an instance of an oidceid app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=OidcEidConfig, app_name=name, ns="webapp", test_config=test_config)

    # Load acs actions on app init
    from . import callback_actions  # noqa: F401

    app = OidcEidApp(config)

    app.logger.info(f"Init {app}...")

    # Register views
    from eduid.webapp.oidceid.views import oidceid_views

    app.register_blueprint(oidceid_views)

    app.redirect_uri = get_external_url(app, CALLBACK_ENDPOINT)
    redirect_uris = [app.redirect_uri]
    for provider in config.providers:
        app.oidc_clients[provider.issuer] = init_oidc_rp_client(
            app=app, name="oidceid", config=provider, redirect_uris=redirect_uris
        )

    # Register view path that should not be authorized
    no_authn_views(
        config,
        ["/mfa-authenticate", "/mfa-register", "/get-status", "/authn-callback"],
    )

    app.logger.info(f"{name!s} initialized")
    return app
