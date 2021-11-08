# -*- coding: utf-8 -*-
import json
from typing import Any, Dict, List, Mapping, Optional
from unittest.mock import patch

from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.api.utils import hash_password
from eduid.webapp.security.app import SecurityApp, security_init_app
from eduid.webapp.security.helpers import SecurityMsg


class ChangePasswordTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    app: SecurityApp

    def setUp(self, *args, users: Optional[List[str]] = None, copy_user_to_private: bool = False, **kwargs):
        self.test_user_eppn = 'hubba-bubba'
        self.test_user_email = 'johnsmith@example.com'
        self.test_user_nin = '197801011235'
        super(ChangePasswordTests, self).setUp(*args, users=users, copy_user_to_private=True, **kwargs)

    def load_app(self, config: Mapping[str, Any]) -> SecurityApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return security_init_app('testing', config)

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        config.update(
            {
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'vccs_url': 'http://vccs',
                'email_code_timeout': 7200,
                'phone_code_timeout': 600,
                'password_length': 12,
                'password_entropy': 25,
                'chpass_timeout': 600,
                'fido2_rp_id': 'example.org',
                'dashboard_url': 'https://dashboard.dev.eduid.se',
            }
        )
        return config

    def tearDown(self):
        super(ChangePasswordTests, self).tearDown()
        with self.app.app_context():
            self.app.central_userdb._drop_whole_collection()

    # parameterized test methods

    def _get_suggested(self):
        """
        GET a suggested password.
        """
        response = self.browser.get('/change-password/suggested-password')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:

            return client.get('/change-password/suggested-password')

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def _change_password(
        self, mock_request_user_sync: Any, data1: Optional[dict] = None,
    ):
        """
        To change the password of the test user, POST old and new passwords,
        mocking the required re-authentication (by setting a flag in the session).

        :param data1: to control the data sent to the change-password endpoint.
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    data = {'new_password': '0ieT/(.edW76', 'old_password': '5678', 'csrf_token': sess.get_csrf_token()}
                    if data1 == {}:
                        data = {'csrf_token': sess.get_csrf_token()}
                    elif data1 is not None:
                        data.update(data1)

                return client.post(
                    '/change-password/set-password', data=json.dumps(data), content_type=self.content_type_json
                )

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def _get_suggested_and_change(
        self, mock_request_user_sync: Any, data1: Optional[dict] = None, correct_old_password: bool = True,
    ):
        """
        To change the password of the test user using a suggested password,
        first GET a suggested password, and then POST old and new passwords,
        mocking the required re-authentication (by setting a flag in the session).

        :param data1: to control the data sent to the change-password endpoint.
        :param correct_old_password: mock result for authentication with old password
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with patch('eduid.webapp.common.authn.vccs.VCCSClient.add_credentials', return_value=True):
                    with patch('eduid.webapp.common.authn.vccs.VCCSClient.revoke_credentials', return_value=True):
                        with patch(
                            'eduid.webapp.common.authn.vccs.VCCSClient.authenticate', return_value=correct_old_password
                        ):
                            response2 = client.get('/change-password/suggested-password')
                            passwd = json.loads(response2.data)
                            self.assertEqual(
                                passwd['type'], 'GET_CHANGE_PASSWORD_CHANGE_PASSWORD_SUGGESTED_PASSWORD_SUCCESS'
                            )
                            password = passwd['payload']['suggested_password']

                            with client.session_transaction() as sess:
                                sess.security.generated_password_hash = hash_password(password)
                                data = {
                                    'csrf_token': sess.get_csrf_token(),
                                    'new_password': password,
                                    'old_password': '5678',
                                }
                            if data1 is not None:
                                data.update(data1)
                            return client.post(
                                '/change-password/set-password',
                                data=json.dumps(data),
                                content_type=self.content_type_json,
                            )

    # actual tests
    def test_user_setup(self):
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    def test_app_starts(self):
        self.assertEqual(self.app.conf.app_name, 'testing')
        response1 = self.browser.get('/change-password/suggested-password')
        assert response1.status_code == 302  # redirect to login
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            response2 = client.get('/change-password/suggested-password')
            assert response2.status_code == 200  # authenticated response

    def test_get_suggested(self):
        response = self._get_suggested()
        passwd = json.loads(response.data)
        self.assertEqual(passwd['type'], "GET_CHANGE_PASSWORD_CHANGE_PASSWORD_SUGGESTED_PASSWORD_SUCCESS")

    @patch('eduid.webapp.security.views.change_password.change_password')
    def test_change_passwd(self, mock_change_password):
        mock_change_password.return_value = True

        response = self._change_password()
        self._check_success_response(
            response,
            type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_SUCCESS',
            msg=SecurityMsg.change_password_success,
        )

    def test_change_passwd_no_data(self):
        response = self._change_password(data1={})
        self._check_error_response(
            response,
            type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL',
            error={
                'new_password': ['Missing data for required field.'],
                'old_password': ['Missing data for required field.'],
            },
        )

    def test_change_passwd_empty_data(self):
        data1 = {'new_password': '', 'old_password': ''}
        response = self._change_password(data1=data1)
        self._check_success_response(
            response, type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL', msg=SecurityMsg.chpass_no_data
        )

    @patch('eduid.webapp.security.views.change_password.change_password')
    def test_change_passwd_no_csrf(self, mock_change_password):
        mock_change_password.return_value = True

        data1 = {'csrf_token': ''}
        response = self._change_password(data1=data1)
        self._check_error_response(
            response,
            type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL',
            error={'csrf_token': ['CSRF failed to validate']},
        )

    @patch('eduid.webapp.security.views.change_password.change_password')
    def test_change_passwd_wrong_csrf(self, mock_change_password):
        mock_change_password.return_value = True

        data1 = {'csrf_token': 'wrong-token'}
        response = self._change_password(data1=data1)
        self._check_error_response(
            response,
            type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL',
            error={'csrf_token': ['CSRF failed to validate']},
        )

    @patch('eduid.webapp.security.views.change_password.change_password')
    def test_change_passwd_weak(self, mock_change_password):
        mock_change_password.return_value = True

        data1 = {'new_password': 'pw'}
        response = self._change_password(data1=data1)
        self._check_error_response(
            response, type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL', msg=SecurityMsg.chpass_weak,
        )

    def test_get_suggested_and_change(self):
        response = self._get_suggested_and_change()
        self._check_success_response(
            response=response, type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_SUCCESS'
        )

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertTrue(user.credentials.to_list()[-1].is_generated)

    def test_get_suggested_and_change_custom(self):
        data1 = {'new_password': '0ieT/(.edW76'}
        response = self._get_suggested_and_change(data1=data1)
        self._check_success_response(
            response=response, type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_SUCCESS'
        )

        # check that the password is marked as generated in this case changed
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    def test_get_suggested_and_change_wrong_csrf(self):
        data1 = {'csrf_token': 'wrong-token'}
        response = self._get_suggested_and_change(data1=data1)

        self._check_error_response(
            response,
            type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL',
            error={'csrf_token': ['CSRF failed to validate']},
        )

        # check that the password is not marked as generated, in this case changed
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    def test_get_suggested_and_change_wrong_old_pw(self):
        response = self._get_suggested_and_change(correct_old_password=False)
        self._check_error_response(
            response, type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL', msg=SecurityMsg.unrecognized_pw,
        )

        # check that the password is not marked as generated, in this case changed
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    def test_get_suggested_and_change_weak_new_pw(self):
        data1 = {'new_password': 'pw'}
        response = self._get_suggested_and_change(data1=data1)
        self._check_error_response(
            response, type_='POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL', msg=SecurityMsg.chpass_weak,
        )

        # check that the password is not marked as generated, in this case changed
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)
