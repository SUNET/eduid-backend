# -*- coding: utf-8 -*-
import json
from typing import Any, List, Mapping, Optional
from unittest.mock import patch

from eduid.webapp.common.api.testing import EduidAPITestCase

__author__ = 'lundberg'

from eduid.webapp.ladok.app import LadokApp, init_ladok_app


class MockResponse(object):
    def __init__(self, status_code: int, data: Mapping):
        self._data = data
        self.status_code = status_code
        self.text = json.dumps(self._data)

    def json(self):
        return self._data


class LadokTests(EduidAPITestCase):

    app: LadokApp

    def setUp(self, *args, users: Optional[List[str]] = None, copy_user_to_private: bool = False, **kwargs):
        self.test_user_eppn = 'hubba-bubba'
        self.test_unverified_user_eppn = 'hubba-baar'
        self.test_user_nin = '197801011234'

        self.university_data = {
            'data': {
                'school_names': {
                    'ab': {'long_name_sv': 'Lärosätesnamn', 'long_name_en': 'University Name'},
                    'cd': {'long_name_sv': 'Annat Lärosätesnamn', 'long_name_en': 'Another University Name'},
                }
            },
            'error': None,
        }

        self.universities_response = MockResponse(200, self.university_data)

        super().setUp(users=['hubba-bubba', 'hubba-baar'])

    def load_app(self, config: Mapping[str, Any]) -> LadokApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        with patch('requests.get') as mock_response:
            mock_response.return_value = self.universities_response
            return init_ladok_app('testing', config)

    def update_config(self, app_config):
        app_config['ladok_client'] = {'url': 'http://localhost'}
        return app_config

    def test_authenticate(self):
        response = self.browser.get('/')
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            response = browser.get('/')
        self._check_success_response(response, type_='GET_LADOK_SUCCESS')
