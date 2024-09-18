from collections.abc import Mapping
from typing import Any

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.logging import merge_config
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.testing import EduidAPITestCase

__author__ = "lundberg"

from eduid.common.config.parsers import load_config


class LoggingTestApp(EduIDBaseApp):
    pass


class LoggingTest(EduidAPITestCase):
    app: LoggingTestApp

    def load_app(self, test_config: Mapping[str, Any]) -> LoggingTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        config = load_config(typ=EduIDBaseAppConfig, app_name="test_app", ns="webapp", test_config=test_config)
        return LoggingTestApp(config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        return config

    def tearDown(self):
        pass

    def test_merge_config(self):
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
        self.assertIsNone(base_config["formatters"].get("test", None))
        self.assertEqual(len(base_config["formatters"]), 1)
        self.assertIsNotNone(settings_config["formatters"].get("test", None))
        self.assertEqual(base_config["handlers"]["console"]["formatter"], "default")
        self.assertEqual(base_config["handlers"]["console"]["filters"], ["app_filter", "user_filter"])
        self.assertEqual(settings_config["handlers"]["console"]["formatter"], "test")
        self.assertEqual(settings_config["handlers"]["console"]["filters"], ["test_filter"])

        res = merge_config(base_config, settings_config)

        self.assertIsNotNone(res["formatters"].get("test", None))
        self.assertEqual(len(res["formatters"]), 2)
        self.assertEqual(res["formatters"]["test"]["format"], "%(levelname)s: Module: %(name)s Msg: %(message)s")
        self.assertEqual(res["handlers"]["console"]["formatter"], "test")
        self.assertEqual(res["handlers"]["console"]["filters"], ["test_filter"])
