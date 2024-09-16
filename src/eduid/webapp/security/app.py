from collections.abc import Mapping
from typing import Any, Optional, cast

from fido_mds import FidoMetadataStore
from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.queue.db.message import MessageDB
from eduid.userdb.authninfo import AuthnInfoDB
from eduid.userdb.logs import ProofingLog
from eduid.userdb.logs.db import FidoMetadataLog
from eduid.userdb.security import PasswordResetStateDB, SecurityUserDB
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.security.settings.common import SecurityConfig


class SecurityApp(AuthnBaseApp):
    def __init__(self, config: SecurityConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.conf = config

        self.am_relay = AmRelay(config)
        self.msg_relay = MsgRelay(config)

        self.fido_mds = FidoMetadataStore()

        self.private_userdb = SecurityUserDB(config.mongo_uri)
        self.authninfo_db = AuthnInfoDB(config.mongo_uri)
        self.password_reset_state_db = PasswordResetStateDB(config.mongo_uri)
        self.proofing_log = ProofingLog(config.mongo_uri)
        self.fido_metadata_log = FidoMetadataLog(config.mongo_uri)
        self.messagedb = MessageDB(config.mongo_uri)


current_security_app: SecurityApp = cast(SecurityApp, current_app)


def security_init_app(name: str = "security", test_config: Optional[Mapping[str, Any]] = None) -> SecurityApp:
    """
    Create an instance of an eduid security (passwords) app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config. Used in test cases.
    """
    config = load_config(typ=SecurityConfig, app_name=name, ns="webapp", test_config=test_config)

    app = SecurityApp(config)

    app.logger.info(f"Init {app}...")

    from eduid.webapp.common.authn.utils import no_authn_views
    from eduid.webapp.security.views.change_password import change_password_views
    from eduid.webapp.security.views.security import security_views
    from eduid.webapp.security.views.webauthn import webauthn_views

    # Register view path that should not be authorized
    no_authn_views(
        config,
        [
            "/webauthn/approved-security-keys",
        ],
    )

    app.register_blueprint(security_views)
    app.register_blueprint(webauthn_views)
    app.register_blueprint(change_password_views)

    return app
