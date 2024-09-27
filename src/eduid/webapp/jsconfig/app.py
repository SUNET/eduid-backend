from collections.abc import Mapping
from typing import Any, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.jsconfig.settings.common import JSConfigConfig


class JSConfigApp(EduIDBaseApp):
    def __init__(self, config: JSConfigConfig, **kwargs: Any):
        kwargs["init_central_userdb"] = False
        kwargs["static_folder"] = None

        super().__init__(config, **kwargs)

        self.conf = config


current_jsconfig_app: JSConfigApp = cast(JSConfigApp, current_app)


def jsconfig_init_app(name: str = "jsconfig", test_config: Mapping[str, Any] | None = None) -> JSConfigApp:
    """
    Create an instance of an eduid jsconfig data app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=JSConfigConfig, app_name=name, ns="webapp", test_config=test_config)
    app = JSConfigApp(config)

    from eduid.webapp.jsconfig.views import jsconfig_views

    app.register_blueprint(jsconfig_views)

    app.logger.info(f"Init {app}...")
    return app
