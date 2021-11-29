# -*- coding: utf-8 -*-
import json
from typing import Any, List, Mapping, Optional
from unittest.mock import patch
from uuid import uuid4

from eduid.webapp.common.api.testing import EduidAPITestCase

__author__ = 'lundberg'

from eduid.webapp.ladok.app import LadokApp, init_ladok_app
from eduid.webapp.ladok.eduid_ladok_client import StudentInfoData, StudentInfoResponse


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
        self.student_external_uid = str(uuid4())

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

    def test_get_universities(self):
        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            response = browser.get('/universities')
        expected_payload = {
            'universities': [
                {'abbr': 'ab', 'name_en': 'University Name', 'name_sv': 'Lärosätesnamn'},
                {'abbr': 'cd', 'name_en': 'Another University Name', 'name_sv': 'Annat Lärosätesnamn'},
            ]
        }
        self._check_success_response(response, type_='GET_LADOK_UNIVERSITIES_SUCCESS', payload=expected_payload)

    @patch('requests.post')
    def test_link_user(self, mock_response):

        student_info = StudentInfoData(
            ladok_externt_uid=self.student_external_uid,
            esi=f'urn:schac:personalUniqueCode:int:esi:ladok.se:externtstudentuid-{self.student_external_uid}',
        )
        mock_response.return_value = MockResponse(
            status_code=200, data=StudentInfoResponse(error=None, data=student_info).dict(by_alias=True)
        )

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert len(user.nins.verified) == 2

        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            with browser.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            response = browser.post('/link-user', json={'csrf_token': csrf_token, 'university_abbr': 'ab'})
        self._check_success_response(response, type_='POST_LADOK_LINK_USER_SUCCESS')
