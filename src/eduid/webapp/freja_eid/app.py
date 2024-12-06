from collections.abc import Mapping
from typing import Any, cast

from authlib.integrations.flask_client import OAuth
from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing.db import FrejaEIDProofingUserDB
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.freja_eid.helpers import SessionOAuthCache
from eduid.webapp.freja_eid.settings.common import FrejaEIDConfig

__author__ = "lundberg"


class FrejaEIDApp(AuthnBaseApp):
    def __init__(self, config: FrejaEIDConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config
        # Init dbs
        self.private_userdb = FrejaEIDProofingUserDB(self.conf.mongo_uri)
        self.proofing_log = ProofingLog(config.mongo_uri)
        # Init celery
        self.am_relay = AmRelay(config)
        self.msg_relay = MsgRelay(config)

        # Initialize the oidc_client
        self.oidc_client = OAuth(self, cache=SessionOAuthCache())
        client_kwargs = {}
        if self.conf.freja_eid_client.scopes:
            client_kwargs["scope"] = " ".join(self.conf.freja_eid_client.scopes)
        if self.conf.freja_eid_client.code_challenge_method:
            client_kwargs["code_challenge_method"] = self.conf.freja_eid_client.code_challenge_method
        authorize_params = {}
        if self.conf.freja_eid_client.acr_values:
            authorize_params["acr_values"] = " ".join(self.conf.freja_eid_client.acr_values)
        self.oidc_client.register(
            name="freja_eid",
            client_id=self.conf.freja_eid_client.client_id,
            client_secret=self.conf.freja_eid_client.client_secret,
            client_kwargs=client_kwargs,
            authorize_params=authorize_params,
            server_metadata_url=f"{self.conf.freja_eid_client.issuer}/.well-known/openid-configuration",
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
    from . import callback_actions

    # Make sure pycharm doesn't think the import above is unused and removes it
    if callback_actions.__author__:
        pass

    app = FrejaEIDApp(config)

    app.logger.info(f"Init {app}...")

    # Register views
    from eduid.webapp.freja_eid.views import freja_eid_views

    app.register_blueprint(freja_eid_views)

    app.logger.info(f"{name!s} initialized")
    return app
