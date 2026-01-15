from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.queue.db.message import MessageDB
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing import EmailProofingStateDB, EmailProofingUserDB
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.email.settings.common import EmailConfig


class EmailApp(AuthnBaseApp):
    def __init__(self, config: EmailConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        # Init celery
        self.am_relay = AmRelay(config)

        self.private_userdb = EmailProofingUserDB(config.mongo_uri, auto_expire=config.private_userdb_auto_expire)
        self.proofing_statedb = EmailProofingStateDB(config.mongo_uri, auto_expire=config.state_db_auto_expire)
        self.proofing_log = ProofingLog(config.mongo_uri)
        self.messagedb = MessageDB(config.mongo_uri)


current_email_app: EmailApp = cast(EmailApp, current_app)


def email_init_app(name: str = "email", test_config: Mapping[str, Any] | None = None) -> EmailApp:
    """
    Create an instance of an eduid email app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=EmailConfig, app_name=name, ns="webapp", test_config=test_config)

    app = EmailApp(config)

    app.logger.info(f"Init {app}...")

    from eduid.webapp.email.views import email_views

    app.register_blueprint(email_views)

    return app
