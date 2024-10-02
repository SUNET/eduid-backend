from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing import PhoneProofingStateDB, PhoneProofingUserDB
from eduid.webapp.common.api import translation
from eduid.webapp.common.api.captcha import init_captcha
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.phone.settings.common import PhoneConfig


class PhoneApp(AuthnBaseApp):
    def __init__(self, config: PhoneConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        # Init celery
        self.am_relay = AmRelay(config)
        self.msg_relay = MsgRelay(config)

        self.private_userdb = PhoneProofingUserDB(config.mongo_uri)
        self.proofing_statedb = PhoneProofingStateDB(config.mongo_uri)
        self.proofing_log = ProofingLog(config.mongo_uri)

        self.babel = translation.init_babel(self)
        self.captcha = init_captcha(config)


current_phone_app: PhoneApp = cast(PhoneApp, current_app)


def phone_init_app(name: str = "phone", test_config: Mapping[str, Any] | None = None) -> PhoneApp:
    """
    Create an instance of an eduid phone app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=PhoneConfig, app_name=name, ns="webapp", test_config=test_config)

    app = PhoneApp(config)

    app.logger.info(f"Init {name} app...")

    from eduid.webapp.phone.views import phone_views

    app.register_blueprint(phone_views)

    return app
