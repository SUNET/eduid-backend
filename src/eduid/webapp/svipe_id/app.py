from collections.abc import Mapping
from typing import Any, cast

from authlib.integrations.flask_client import OAuth
from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing.db import SvideIDProofingUserDB
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.svipe_id.helpers import SessionOAuthCache
from eduid.webapp.svipe_id.settings.common import SvipeIdConfig

__author__ = "lundberg"


class SvipeIdApp(AuthnBaseApp):
    def __init__(self, config: SvipeIdConfig, **kwargs: Any):
        super().__init__(config, **kwargs)

        self.conf = config
        # Init dbs
        self.private_userdb = SvideIDProofingUserDB(self.conf.mongo_uri)
        self.proofing_log = ProofingLog(config.mongo_uri)
        # Init celery
        self.am_relay = AmRelay(config)

        # Initialize the oidc_client
        self.oidc_client = OAuth(self, cache=SessionOAuthCache())
        client_kwargs = {}
        if self.conf.svipe_client.scopes:
            client_kwargs["scope"] = " ".join(self.conf.svipe_client.scopes)
        if self.conf.svipe_client.code_challenge_method:
            client_kwargs["code_challenge_method"] = self.conf.svipe_client.code_challenge_method
        authorize_params = {}
        if self.conf.svipe_client.acr_values:
            authorize_params["acr_values"] = " ".join(self.conf.svipe_client.acr_values)
        self.oidc_client.register(
            name="svipe",
            client_id=self.conf.svipe_client.client_id,
            client_secret=self.conf.svipe_client.client_secret,
            client_kwargs=client_kwargs,
            authorize_params=authorize_params,
            server_metadata_url=f"{self.conf.svipe_client.issuer}/.well-known/openid-configuration",
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
    from . import callback_actions

    # Make sure pycharm doesn't think the import above is unused and removes it
    if callback_actions.__author__:
        pass

    app = SvipeIdApp(config)

    app.logger.info(f"Init {app}...")

    # Register views
    from eduid.webapp.svipe_id.views import svipe_id_views

    app.register_blueprint(svipe_id_views)

    app.logger.info(f"{name!s} initialized")
    return app
