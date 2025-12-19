from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing import LetterProofingStateDB, LetterProofingUserDB
from eduid.webapp.common.api import translation
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.letter_proofing.ekopost import Ekopost
from eduid.webapp.letter_proofing.settings.common import LetterProofingConfig

__author__ = "lundberg"


class LetterProofingApp(AuthnBaseApp):
    def __init__(self, config: LetterProofingConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        # Init dbs
        self.private_userdb = LetterProofingUserDB(config.mongo_uri, auto_expire=config.private_userdb_auto_expire)
        self.proofing_statedb = LetterProofingStateDB(config.mongo_uri, auto_expire=config.state_db_auto_expire)
        self.proofing_log = ProofingLog(config.mongo_uri)

        # Init celery
        self.msg_relay = MsgRelay(config)
        self.am_relay = AmRelay(config)

        # Init babel
        self.babel = translation.init_babel(self)

        # Initiate external modules
        self.ekopost = Ekopost(config)


current_letterp_app = cast(LetterProofingApp, current_app)


def init_letter_proofing_app(
    name: str = "letter_proofing", test_config: Mapping[str, Any] | None = None
) -> LetterProofingApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=LetterProofingConfig, app_name=name, ns="webapp", test_config=test_config)

    app = LetterProofingApp(config)

    app.logger.info(f"Init {name} app...")

    # Register views
    from eduid.webapp.letter_proofing.views import letter_proofing_views

    app.register_blueprint(letter_proofing_views)

    return app
