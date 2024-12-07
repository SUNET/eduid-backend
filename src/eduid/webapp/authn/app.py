from collections.abc import Mapping
from typing import Any

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.webapp.authn.settings.common import AuthnConfig
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.authn.utils import get_saml2_config


class AuthnApp(EduIDBaseApp):
    def __init__(self, config: AuthnConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        self.saml2_config = get_saml2_config(config.saml2_settings_module)


def get_current_app() -> AuthnApp:
    """Teach pycharm about AuthnApp"""
    return current_app  # type: ignore[return-value]


current_authn_app = get_current_app()


def authn_init_app(name: str = "authn", test_config: Mapping[str, Any] | None = None) -> AuthnApp:
    """
    Create an instance of an authentication app.

    :param name: The name of the instance, it will affect the configuration file
                 loaded from the filesystem.
    :param test_config: any additional configuration settings. Specially useful
                   in test cases
    """
    config = load_config(typ=AuthnConfig, app_name=name, ns="webapp", test_config=test_config)

    app = AuthnApp(config)

    app.logger.info(f"Init {app}...")

    from eduid.webapp.authn.views import authn_views

    app.register_blueprint(authn_views)

    return app
