from collections.abc import Mapping
from typing import Any

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.logging import merge_config
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.testing import EduidAPITestCase

__author__ = "lundberg"

from eduid.common.config.parsers import load_config


class LoggingTestApp(EduIDBaseApp[EduIDBaseAppConfig]):
    pass


class LoggingTest(EduidAPITestCase[LoggingTestApp]):
    app: LoggingTestApp

    def load_app(self, config: Mapping[str, Any]) -> LoggingTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        logging_config = load_config(typ=EduIDBaseAppConfig, app_name="test_app", ns="webapp", test_config=config)
        return LoggingTestApp(logging_config)

    def tearDown(self) -> None:
        """Override parent tearDown to prevent default cleanup."""

    def test_merge_config(self) -> None:
        base_config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "()": "eduid.webapp.common.api.logging.EduidFormatter",
                    "fmt": "cfg://local_context.format",
                },
            },
            "filters": {
                "app_filter": {
                    "()": "eduid.webapp.common.api.logging.AppFilter",
                    "app_name": "cfg://local_context.app_name",
                },
                "user_filter": {
                    "()": "eduid.webapp.common.api.logging.UserFilter",
                },
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "level": "cfg://local_context.level",
                    "formatter": "default",
                    "filters": ["app_filter", "user_filter"],
                },
            },
            "root": {
                "handlers": ["console"],
                "level": "cfg://local_context.level",
            },
        }
        settings_config = {
            "formatters": {"test": {"format": "%(levelname)s: Module: %(name)s Msg: %(message)s"}},
            "handlers": {"console": {"formatter": "test", "filters": ["test_filter"]}},
        }
        assert isinstance(base_config["formatters"], dict)
        assert isinstance(settings_config["formatters"], dict)
        assert isinstance(base_config["handlers"], dict)
        assert isinstance(settings_config["handlers"], dict)
        assert base_config["formatters"].get("test", None) is None
        assert len(base_config["formatters"]) == 1
        assert settings_config["formatters"].get("test", None) is not None
        assert base_config["handlers"]["console"]["formatter"] == "default"
        assert base_config["handlers"]["console"]["filters"] == ["app_filter", "user_filter"]
        assert settings_config["handlers"]["console"]["formatter"] == "test"
        assert settings_config["handlers"]["console"]["filters"] == ["test_filter"]

        res = merge_config(base_config, settings_config)

        assert res["formatters"].get("test", None) is not None
        assert len(res["formatters"]) == 2
        assert res["formatters"]["test"]["format"] == "%(levelname)s: Module: %(name)s Msg: %(message)s"
        assert res["handlers"]["console"]["formatter"] == "test"
        assert res["handlers"]["console"]["filters"] == ["test_filter"]
