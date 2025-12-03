from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb.logs.db import ProofingLog
from eduid.userdb.proofing.db import ProofingUserDB
from eduid.userdb.proofing.user import ProofingUser
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.common.authn.utils import get_saml2_config, no_authn_views
from eduid.webapp.samleid.settings.common import SamleidConfig

__author__ = "lundberg"


class SamleidProofingUserDB(ProofingUserDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_samleid") -> None:
        super().__init__(db_uri, db_name)


class SamleidApp(AuthnBaseApp):
    def __init__(self, config: SamleidConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        self.saml2_config = get_saml2_config(config.saml2_settings_module)

        # Init dbs
        self.private_userdb = SamleidProofingUserDB(config.mongo_uri)
        self.proofing_log = ProofingLog(config.mongo_uri)

        # Init celery
        self.am_relay = AmRelay(config)
        self.msg_relay = MsgRelay(config)


current_samleid_app: SamleidApp = cast(SamleidApp, current_app)


def init_samleid_app(name: str = "samleid", test_config: Mapping[str, Any] | None = None) -> SamleidApp:
    """
    Create an instance of a samleid app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=SamleidConfig, app_name=name, ns="webapp", test_config=test_config)

    # Load acs actions on app init
    from . import acs_actions

    # Make sure pycharm doesn't think the import above is unused and removes it
    if acs_actions.__author__:
        pass

    app = SamleidApp(config)

    app.logger.info(f"Init {app}...")

    # Register views
    from eduid.webapp.samleid.views import samleid_views

    app.register_blueprint(samleid_views)

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
