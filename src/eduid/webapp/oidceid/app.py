from collections.abc import Mapping
from typing import Any, cast

from flask import Flask, current_app
from werkzeug.routing import BuildError

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
CALLBACK_PATH = "/authn-callback"


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


current_oidceid_app = cast(OidcEidApp, current_app)


def _callback_url(app: Flask) -> str:
    """
    The absolute URL of the callback endpoint, registered at the OPs.

    The callback view is added together with the rest of the views. As long as the endpoint is not registered
    the URL is built from the same config values, so the app can still be created.
    """
    try:
        return get_external_url(app, CALLBACK_ENDPOINT)
    except BuildError:
        app.logger.warning(f"Endpoint {CALLBACK_ENDPOINT} is not registered, building callback URL from config")
        server_name = app.config.get("SERVER_NAME") or "localhost"
        scheme = app.config.get("PREFERRED_URL_SCHEME") or "https"
        root = (app.config.get("APPLICATION_ROOT") or "/").rstrip("/")
        return f"{scheme}://{server_name}{root}{CALLBACK_PATH}"


def init_oidceid_app(name: str = "oidceid", test_config: Mapping[str, Any] | None = None) -> OidcEidApp:
    """
    Create an instance of an oidceid app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=OidcEidConfig, app_name=name, ns="webapp", test_config=test_config)

    app = OidcEidApp(config)

    app.logger.info(f"Init {app}...")

    # Register views
    from eduid.webapp.oidceid.views import oidceid_views

    app.register_blueprint(oidceid_views)

    redirect_uris = [_callback_url(app)]
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
