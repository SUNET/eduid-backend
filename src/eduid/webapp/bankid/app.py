from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb.logs.db import ProofingLog
from eduid.userdb.proofing.db import BankIDProofingUserDB
from eduid.webapp.bankid.settings.common import BankIDConfig
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.common.authn.utils import get_saml2_config, no_authn_views

__author__ = "lundberg"


class BankIDApp(AuthnBaseApp):
    def __init__(self, config: BankIDConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        self.saml2_config = get_saml2_config(config.saml2_settings_module)

        # Init dbs
        self.private_userdb = BankIDProofingUserDB(config.mongo_uri)
        self.proofing_log = ProofingLog(config.mongo_uri)

        # Init celery
        self.am_relay = AmRelay(config)
        self.msg_relay = MsgRelay(config)


current_bankid_app: BankIDApp = cast(BankIDApp, current_app)


def init_bankid_app(name: str = "bankid", test_config: Mapping[str, Any] | None = None) -> BankIDApp:
    """
    Create an instance of an bankid app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=BankIDConfig, app_name=name, ns="webapp", test_config=test_config)

    # Load acs actions on app init
    from . import acs_actions

    # Make sure pycharm doesn't think the import above is unused and removes it
    if acs_actions.__author__:
        pass

    app = BankIDApp(config)

    app.logger.info(f"Init {app}...")

    # Register views
    from eduid.webapp.bankid.views import bankid_views

    app.register_blueprint(bankid_views)

    # Register view path that should not be authorized
    no_authn_views(
        config,
        [
            "/saml2-metadata",
            "/saml2-acs",
            "/mfa-authentication",
            "/mfa-authenticate",
            "/get-status",
        ],
    )

    return app
