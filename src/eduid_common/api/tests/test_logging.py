# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Optional

from eduid_common.api.app import EduIDBaseApp
from eduid_common.api.logging import merge_config
from eduid_common.api.testing import EduidAPITestCase

__author__ = 'lundberg'

from eduid_common.config.base import FlaskConfig


class LoggingTestApp(EduIDBaseApp):
    def __init__(self, name: str, config: Dict[str, Any], **kwargs):
        self.config = FlaskConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)


class LoggingTest(EduidAPITestCase):
    def setUp(
        self,
        users: Optional[List[str]] = None,
        copy_user_to_private: bool = False,
        am_settings: Optional[Dict[str, Any]] = None,
    ):

        super(LoggingTest, self).setUp(users=users, copy_user_to_private=copy_user_to_private, am_settings=am_settings)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return LoggingTestApp('test_app', config)

    def update_config(self, config):
        return config

    def tearDown(self):
        pass

    def test_merge_config(self):
        base_config = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'default': {'()': 'eduid_common.api.logging.EduidFormatter', 'fmt': 'cfg://local_context.format'},
            },
            'filters': {
                'app_filter': {'()': 'eduid_common.api.logging.AppFilter', 'app_name': 'cfg://local_context.app_name',},
                'user_filter': {'()': 'eduid_common.api.logging.UserFilter',},
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'level': 'cfg://local_context.level',
                    'formatter': 'default',
                    'filters': ['app_filter', 'user_filter'],
                },
            },
            'root': {'handlers': ['console'], 'level': 'cfg://local_context.level',},
        }
        settings_config = {
            'formatters': {'test': {'format': '%(levelname)s: Module: %(name)s Msg: %(message)s'}},
            'handlers': {'console': {'formatter': 'test', 'filters': ['test_filter']}},
        }
        self.assertIsNone(base_config['formatters'].get('test', None))
        self.assertEqual(len(base_config['formatters']), 1)
        self.assertIsNotNone(settings_config['formatters'].get('test', None))
        self.assertEqual(base_config['handlers']['console']['formatter'], 'default')
        self.assertEqual(base_config['handlers']['console']['filters'], ['app_filter', 'user_filter'])
        self.assertEqual(settings_config['handlers']['console']['formatter'], 'test')
        self.assertEqual(settings_config['handlers']['console']['filters'], ['test_filter'])

        res = merge_config(base_config, settings_config)

        self.assertIsNotNone(res['formatters'].get('test', None))
        self.assertEqual(len(res['formatters']), 2)
        self.assertEqual(res['formatters']['test']['format'], '%(levelname)s: Module: %(name)s Msg: %(message)s')
        self.assertEqual(res['handlers']['console']['formatter'], 'test')
        self.assertEqual(res['handlers']['console']['filters'], ['test_filter'])
