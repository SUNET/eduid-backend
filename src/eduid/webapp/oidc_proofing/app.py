from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.mail_relay import MailRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing import OidcProofingStateDB, OidcProofingUserDB
from eduid.webapp.common.api import oidc, translation
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.common.authn.utils import no_authn_views
from eduid.webapp.oidc_proofing.settings.common import OIDCProofingConfig

__author__ = "lundberg"


class OIDCProofingApp(AuthnBaseApp):
    def __init__(self, config: OIDCProofingConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        # Provide type, although the actual assignment happens in init_oidc_proofing_app below
        self.oidc_client: oidc.Client

        # Init celery
        self.msg_relay = MsgRelay(config)
        self.am_relay = AmRelay(config)
        self.mail_relay = MailRelay(config)

        # Init babel
        self.babel = translation.init_babel(self)

        # Initialize db
        self.private_userdb = OidcProofingUserDB(self.conf.mongo_uri)
        self.proofing_statedb = OidcProofingStateDB(self.conf.mongo_uri)
        self.proofing_log = ProofingLog(self.conf.mongo_uri)


current_oidcp_app: OIDCProofingApp = cast(OIDCProofingApp, current_app)


def init_oidc_proofing_app(
    name: str = "oidc_proofing", test_config: Mapping[str, Any] | None = None
) -> OIDCProofingApp:
    """
    Create an instance of an oidc proofing app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config. Used in test cases.
    """
    config = load_config(typ=OIDCProofingConfig, app_name=name, ns="webapp", test_config=test_config)

    app = OIDCProofingApp(config)

    app.logger.info(f"Init {app}...")

    from eduid.webapp.oidc_proofing.views import oidc_proofing_views

    app.register_blueprint(oidc_proofing_views)

    # Register view path that should not be authorized
    no_authn_views(config, ["/authorization-response"])

    # Initialize the oidc_client after views to be able to set correct redirect_uris
    app.oidc_client = oidc.init_client(config.client_registration_info, config.provider_configuration_info)

    return app
