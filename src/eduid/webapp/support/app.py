import operator
from collections.abc import Mapping
from datetime import datetime
from typing import Any, cast

from flask import current_app
from jinja2.exceptions import UndefinedError

from eduid.common.config.parsers import load_config
from eduid.common.utils import urlappend
from eduid.userdb.support import db
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.support.settings.common import SupportConfig


class SupportApp(AuthnBaseApp):
    def __init__(self, config: SupportConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        self.support_user_db = db.SupportUserDB(config.mongo_uri)
        self.support_authn_db = db.SupportAuthnInfoDB(config.mongo_uri)
        self.support_proofing_log_db = db.SupportProofingLogDB(config.mongo_uri)
        self.support_signup_db = db.SupportSignupUserDB(config.mongo_uri)
        self.support_letter_proofing_db = db.SupportLetterProofingDB(config.mongo_uri)
        self.support_email_proofing_db = db.SupportEmailProofingDB(config.mongo_uri)


current_support_app: SupportApp = cast(SupportApp, current_app)


def register_template_funcs(app: SupportApp) -> None:
    @app.template_filter("datetimeformat")
    def datetimeformat(value: datetime | None, format: str = "%Y-%m-%d %H:%M %Z") -> str:
        if not value:
            return ""
        return value.strftime(format)

    @app.template_filter("dateformat")
    def dateformat(value: datetime | None, format: str = "%Y-%m-%d") -> str:
        if not value:
            return ""
        return value.strftime(format)

    @app.template_filter("multisort")
    def sort_multi(items: list, *operators: str, **kwargs: Any) -> list:
        # Don't try to sort on missing keys
        keys = list(operators)  # operators is immutable
        for key in operators:
            for item in items:
                if key not in item:
                    app.logger.debug(f"Removed key {key} before sorting.")
                    keys.remove(key)
                    break
        reverse = kwargs.pop("reverse", False)
        try:
            items.sort(key=operator.itemgetter(*keys), reverse=reverse)
        except UndefinedError:  # attribute did not exist
            items = list()
        return items

    @app.template_global()
    def static_url_for(f: str, version: str | None = None) -> str:
        """
        Get the static url for a file and optionally have a version argument appended for cache busting.
        """
        static_url = current_support_app.conf.eduid_static_url
        if version is not None:
            static_url = urlappend(static_url, version)
        return urlappend(static_url, f)

    return None


def support_init_app(name: str = "support", test_config: Mapping[str, Any] | None = None) -> SupportApp:
    """
    Create an instance of an eduid support app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=SupportConfig, app_name=name, ns="webapp", test_config=test_config)

    app = SupportApp(config)

    app.logger.info(f"Init {app}...")

    from eduid.webapp.support.views import support_views

    app.register_blueprint(support_views)

    register_template_funcs(app)

    return app
