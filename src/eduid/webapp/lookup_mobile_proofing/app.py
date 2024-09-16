from collections.abc import Mapping
from typing import Any, Optional, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.lookup_mobile_relay import LookupMobileRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb.logs import ProofingLog
from eduid.userdb.proofing import LookupMobileProofingUserDB
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.lookup_mobile_proofing.settings.common import MobileProofingConfig

__author__ = "lundberg"


class MobileProofingApp(AuthnBaseApp):
    def __init__(self, config: MobileProofingConfig, **kwargs: Any):
        super().__init__(config, **kwargs)

        self.conf = config

        # Init dbs
        self.private_userdb = LookupMobileProofingUserDB(config.mongo_uri)
        self.proofing_log = ProofingLog(config.mongo_uri)

        # Init celery
        self.lookup_mobile_relay = LookupMobileRelay(config)
        self.msg_relay = MsgRelay(config)
        self.am_relay = AmRelay(config)


current_mobilep_app = cast(MobileProofingApp, current_app)


def init_lookup_mobile_proofing_app(
    name: str = "lookup_mobile_proofing", test_config: Optional[Mapping[str, Any]] = None
) -> MobileProofingApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=MobileProofingConfig, app_name=name, ns="webapp", test_config=test_config)

    app = MobileProofingApp(config)

    app.logger.info(f"Init {app}...")

    # Register views
    from eduid.webapp.lookup_mobile_proofing.views import mobile_proofing_views

    app.register_blueprint(mobile_proofing_views)

    return app
