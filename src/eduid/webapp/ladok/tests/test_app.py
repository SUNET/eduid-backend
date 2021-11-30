# -*- coding: utf-8 -*-
import json
from typing import Any, Dict, List, Mapping, Optional
from unittest.mock import patch
from uuid import UUID, uuid4

from flask import Response

from eduid.common.config.base import EduidEnvironment
from eduid.userdb.ladok import Ladok, University
from eduid.webapp.common.api.testing import EduidAPITestCase

__author__ = 'lundberg'

from eduid.webapp.ladok.app import LadokApp, init_ladok_app
from eduid.webapp.ladok.client import Error, LadokUserInfo, LadokUserInfoResponse
from eduid.webapp.ladok.helpers import LadokMsg
from eduid.webapp.ladok.settings.common import LadokConfig


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
        self.ladok_user_external_id = uuid4()

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

        # remove Ladok data from test user
        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        user.ladok = None
        self.app.central_userdb.save(user)

    def load_app(self, config: Mapping[str, Any]) -> LadokApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        with patch('requests.get') as mock_response:
            mock_response.return_value = self.universities_response
            return init_ladok_app('testing', config)

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        config = super().update_config(config=config)
        config['ladok_client'] = {
            'url': 'http://localhost',
            'dev_universities': {'DEV': {'name_sv': 'Testlärosäte', 'name_en': 'Test University'}},
        }
        return config

    def _link_user(self, eppn: str, university_abbr: str) -> Response:
        with self.session_cookie(self.browser, eppn) as browser:
            with browser.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            return browser.post('/link-user', json={'csrf_token': csrf_token, 'university_abbr': university_abbr})

    def _unlink_user(self, eppn: str) -> Response:
        with self.session_cookie(self.browser, eppn) as browser:
            with browser.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            return browser.post('/unlink-user', json={'csrf_token': csrf_token})

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
            'universities': {
                'ab': {'name_en': 'University Name', 'name_sv': 'Lärosätesnamn'},
                'cd': {'name_en': 'Another University Name', 'name_sv': 'Annat Lärosätesnamn'},
            }
        }
        self._check_success_response(response, type_='GET_LADOK_UNIVERSITIES_SUCCESS', payload=expected_payload)

    @patch('requests.post')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_link_user(self, mock_request_user_sync, mock_response):
        mock_request_user_sync.side_effect = self.request_user_sync

        ladok_user_external_id_str = str(self.ladok_user_external_id)
        user_info = LadokUserInfo(
            external_id=ladok_user_external_id_str,
            esi=f'urn:schac:personalUniqueCode:int:esi:ladok.se:externtstudentuid-{ladok_user_external_id_str}',
        )
        mock_response.return_value = MockResponse(
            status_code=200, data=LadokUserInfoResponse(error=None, data=user_info).dict(by_alias=True)
        )

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert len(user.nins.verified) == 2

        university_abbr = 'ab'
        response = self._link_user(eppn=self.test_user_eppn, university_abbr=university_abbr)
        self._check_success_response(response, type_='POST_LADOK_LINK_USER_SUCCESS', msg=LadokMsg.user_linked)

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok.external_id == self.ladok_user_external_id
        assert user.ladok.university.abbr == university_abbr
        assert user.ladok.university.name_sv == self.app.ladok_client.universities.names[university_abbr].name_sv
        assert user.ladok.university.name_en == self.app.ladok_client.universities.names[university_abbr].name_en

        log_docs = self.app.proofing_log._get_documents_by_attr('eduPersonPrincipalName', self.test_user_eppn)
        assert 1 == len(log_docs)

    @patch('requests.post')
    def test_link_user_error_response_from_worker(self, mock_response):
        error = Error(id='internal_server_error', details='some longer error message')
        mock_response.return_value = MockResponse(
            status_code=200, data=LadokUserInfoResponse(error=error, data=None).dict(by_alias=True)
        )

        university_abbr = 'ab'
        response = self._link_user(eppn=self.test_user_eppn, university_abbr=university_abbr)
        self._check_success_response(response, type_='POST_LADOK_LINK_USER_FAIL', msg=LadokMsg.no_ladok_data)

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok is None

        log_docs = self.app.proofing_log._get_documents_by_attr('eduPersonPrincipalName', self.test_user_eppn)
        assert 0 == len(log_docs)

    def test_link_user_no_nin(self):
        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_unverified_user_eppn)
        assert len(user.nins.verified) == 0

        university_abbr = 'ab'
        response = self._link_user(eppn=self.test_unverified_user_eppn, university_abbr=university_abbr)
        self._check_success_response(response, type_='POST_LADOK_LINK_USER_FAIL', msg=LadokMsg.no_verified_nin)

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_unverified_user_eppn)
        assert user.ladok is None

        log_docs = self.app.proofing_log._get_documents_by_attr(
            'eduPersonPrincipalName', self.test_unverified_user_eppn
        )
        assert 0 == len(log_docs)

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_unlink_user(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        # set ladok data for user
        university = University(abbr='ab', name_sv='namn')
        ladok = Ladok(external_id=self.ladok_user_external_id, university=university)
        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        user.ladok = ladok
        self.app.central_userdb.save(user)

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok.external_id == self.ladok_user_external_id
        assert user.ladok.university.abbr == university.abbr

        response = self._unlink_user(eppn=self.test_user_eppn)
        self._check_success_response(response, type_='POST_LADOK_UNLINK_USER_SUCCESS', msg=LadokMsg.user_unlinked)

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok is None

    def test_unlink_user_no_op(self):

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok is None

        response = self._unlink_user(eppn=self.test_user_eppn)
        self._check_success_response(response, type_='POST_LADOK_UNLINK_USER_SUCCESS', msg=LadokMsg.user_unlinked)

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok is None


class LadokDevTests(EduidAPITestCase):

    app: LadokApp

    def setUp(self, *args, users: Optional[List[str]] = None, copy_user_to_private: bool = False, **kwargs):
        self.test_user_eppn = 'hubba-bubba'
        self.test_unverified_user_eppn = 'hubba-baar'
        self.ladok_user_external_id = uuid4()

        super().setUp(users=['hubba-bubba', 'hubba-baar'])

    def load_app(self, config: Mapping[str, Any]) -> LadokApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_ladok_app('testing', config)

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        config = super().update_config(config=config)
        config['environment'] = EduidEnvironment.dev.value
        config['ladok_client'] = {
            'url': 'http://localhost',
            'dev_universities': {'DEV': {'name_sv': 'Testlärosäte', 'name_en': 'Test University'}},
        }
        config['magic_cookie_name'] = 'magic-cookie'
        config['magic_cookie'] = 'magic-cookie'
        return config

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_link_user_backdoor(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        university_abbr = 'DEV'
        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            browser.set_cookie('localhost', key='magic-cookie', value=self.app.conf.magic_cookie)
            with browser.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            response = browser.post('/link-user', json={'csrf_token': csrf_token, 'university_abbr': university_abbr})
        self._check_success_response(response, type_='POST_LADOK_LINK_USER_SUCCESS', msg=LadokMsg.user_linked)

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok.external_id == UUID('00000000-1111-2222-3333-444444444444')
        assert user.ladok.university.abbr == university_abbr
        assert user.ladok.university.name_sv == self.app.ladok_client.universities.names[university_abbr].name_sv
        assert user.ladok.university.name_en == self.app.ladok_client.universities.names[university_abbr].name_en

        log_docs = self.app.proofing_log._get_documents_by_attr('eduPersonPrincipalName', self.test_user_eppn)
        assert 1 == len(log_docs)
