from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.queue.db.message import MessageDB
from eduid.userdb.logs import ProofingLog
from eduid.userdb.reset_password import ResetPasswordStateDB, ResetPasswordUserDB
from eduid.webapp.common.api import translation
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.captcha import init_captcha
from eduid.webapp.reset_password.settings.common import ResetPasswordConfig

__author__ = "eperez"


class ResetPasswordApp(EduIDBaseApp):
    def __init__(self, config: ResetPasswordConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        # Init celery
        self.msg_relay = MsgRelay(config)
        self.am_relay = AmRelay(config)

        self.captcha = init_captcha(config)

        # Init dbs
        self.private_userdb = ResetPasswordUserDB(self.conf.mongo_uri, auto_expire=config.private_userdb_auto_expire)
        self.password_reset_state_db = ResetPasswordStateDB(
            self.conf.mongo_uri, auto_expire=config.state_db_auto_expire
        )
        self.proofing_log = ProofingLog(self.conf.mongo_uri)
        self.messagedb = MessageDB(config.mongo_uri)

        self.babel = translation.init_babel(self)


current_reset_password_app: ResetPasswordApp = cast(ResetPasswordApp, current_app)


def init_reset_password_app(
    name: str = "reset_password", test_config: Mapping[str, Any] | None = None
) -> ResetPasswordApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config. Used in tests.
    """
    config = load_config(typ=ResetPasswordConfig, app_name=name, ns="webapp", test_config=test_config)

    app = ResetPasswordApp(config)

    app.logger.info(f"Init {app}...")

    # Register views
    from eduid.webapp.reset_password.views.reset_password import reset_password_views

    app.register_blueprint(reset_password_views)

    return app
