from collections.abc import Mapping
from typing import Any, Optional, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.userdb.personal_data import PersonalDataUserDB
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.personal_data.settings import PersonalDataConfig


class PersonalDataApp(AuthnBaseApp):
    def __init__(self, config: PersonalDataConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.conf = config

        # Init celery
        self.am_relay = AmRelay(config)

        self.private_userdb = PersonalDataUserDB(config.mongo_uri)


current_pdata_app: PersonalDataApp = cast(PersonalDataApp, current_app)


def pd_init_app(name: str = "personal_data", test_config: Optional[Mapping[str, Any]] = None) -> PersonalDataApp:
    """
    Create an instance of an eduid personal data app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=PersonalDataConfig, app_name=name, ns="webapp", test_config=test_config)

    app = PersonalDataApp(config)

    app.logger.info(f"Init {app}...")

    from eduid.webapp.personal_data.views import pd_views

    app.register_blueprint(pd_views)

    return app
