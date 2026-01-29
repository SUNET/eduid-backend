import json
from collections.abc import Mapping
from http import HTTPStatus
from typing import Any
from unittest.mock import MagicMock, patch

from werkzeug.test import TestResponse

from eduid.common.config.base import FrontendAction
from eduid.userdb.credentials import Password
from eduid.userdb.testing import SetupConfig
from eduid.webapp.common.api.schemas.authn_status import AuthnActionStatus
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.api.utils import hash_password
from eduid.webapp.security.app import SecurityApp, security_init_app
from eduid.webapp.security.helpers import SecurityMsg


class ChangePasswordTests(EduidAPITestCase[SecurityApp]):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self, config: SetupConfig | None = None) -> None:
        self.test_user_eppn = "hubba-bubba"
        self.test_user_email = "johnsmith@example.com"
        self.test_user_nin = "197801011235"
        if config is None:
            config = SetupConfig()
        config.copy_user_to_private = True
        super().setUp(config=config)

    def load_app(self, config: Mapping[str, Any]) -> SecurityApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return security_init_app("testing", config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                "available_languages": {"en": "English", "sv": "Svenska"},
                "vccs_url": "http://vccs",
                "email_code_timeout": 7200,
                "phone_code_timeout": 600,
                "password_length": 12,
                "password_entropy": 25,
                "chpass_reauthn_timeout": 600,
                "fido2_rp_id": "example.org",
                "dashboard_url": "https://dashboard.dev.eduid.se",
            }
        )
        return config

    # parameterized test methods

    def _get_suggested(self, reauthn: int | None = 60) -> TestResponse:
        """
        GET a suggested password.
        """
        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.session_cookie(self.browser, eppn) as client:
            return client.get("/change-password/suggested-password")

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _change_password(
        self,
        mock_request_user_sync: MagicMock,
        data1: dict[str, Any] | None = None,
    ) -> TestResponse:
        """
        To change the password of the test user, POST old and new passwords,
        mocking the required re-authentication (by setting a flag in the session).

        :param data1: to control the data sent to the change-password endpoint.
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.app.test_request_context(), self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                data = {"new_password": "0ieT/(.edW76", "old_password": "5678", "csrf_token": sess.get_csrf_token()}
                if data1 == {}:
                    data = {"csrf_token": sess.get_csrf_token()}
                elif data1 is not None:
                    data.update(data1)

            return client.post("/change-password/set-password", json=data)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _get_suggested_and_change(
        self,
        mock_request_user_sync: MagicMock,
        data1: dict[str, Any] | None = None,
        correct_old_password: bool = True,
    ) -> TestResponse:
        """
        To change the password of the test user using a suggested password,
        first GET a suggested password, and then POST old and new passwords,
        mocking the required re-authentication (by setting a flag in the session).

        :param data1: to control the data sent to the change-password endpoint.
        :param correct_old_password: mock result for authentication with old password
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.app.test_request_context(), self.session_cookie(self.browser, eppn) as client:
            with patch("eduid.webapp.common.authn.vccs.VCCSClient.add_credentials", return_value=True):
                with patch("eduid.webapp.common.authn.vccs.VCCSClient.revoke_credentials", return_value=True):
                    with patch(
                        "eduid.webapp.common.authn.vccs.VCCSClient.authenticate", return_value=correct_old_password
                    ):
                        response2 = client.get("/change-password/suggested-password")
                        passwd = json.loads(response2.data)
                        self.assertEqual(
                            passwd["type"], "GET_CHANGE_PASSWORD_CHANGE_PASSWORD_SUGGESTED_PASSWORD_SUCCESS"
                        )
                        password = passwd["payload"]["suggested_password"]

                        with client.session_transaction() as sess:
                            sess.security.generated_password_hash = hash_password(password)
                            data = {
                                "csrf_token": sess.get_csrf_token(),
                                "new_password": password,
                                "old_password": "5678",
                            }
                        if data1 is not None:
                            data.update(data1)
                        if data["old_password"] is None:
                            del data["old_password"]
                        return client.post(
                            "/change-password/set-password",
                            data=json.dumps(data),
                            content_type=self.content_type_json,
                        )

    # actual tests
    def test_user_setup(self) -> None:
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        password = user.credentials.to_list()[-1]
        assert isinstance(password, Password)
        self.assertFalse(password.is_generated)

    def test_app_starts(self) -> None:
        self.assertEqual(self.app.conf.app_name, "testing")
        response1 = self.browser.get("/change-password/suggested-password")
        assert response1.status_code == HTTPStatus.UNAUTHORIZED
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            response2 = client.get("/change-password/suggested-password")
            assert response2.status_code == HTTPStatus.OK  # authenticated response

    def test_get_suggested_not_logged_in(self) -> None:
        response = self.browser.get("/change-password/suggested-password")
        self.assertEqual(response.status_code, 401)

    @patch("eduid.webapp.security.views.change_password.generate_suggested_password")
    def test_get_suggested(self, mock_generate_password: MagicMock) -> None:
        mock_generate_password.return_value = "test-password"

        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.CHANGE_PW_AUTHN,
        )

        response = self._get_suggested()
        self._check_success_response(
            response,
            type_="GET_CHANGE_PASSWORD_CHANGE_PASSWORD_SUGGESTED_PASSWORD_SUCCESS",
            payload={"suggested_password": "test-password"},
        )

    @patch("eduid.webapp.security.views.change_password.change_password")
    def test_change_passwd(self, mock_change_password: MagicMock) -> None:
        mock_change_password.return_value = True

        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.CHANGE_PW_AUTHN,
        )

        response = self._change_password()
        self._check_success_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_SUCCESS",
            msg=SecurityMsg.change_password_success,
        )

    @patch("eduid.webapp.security.views.change_password.change_password")
    def test_change_passwd_with_login_auth(self, mock_change_password: MagicMock) -> None:
        mock_change_password.return_value = True

        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.LOGIN,
        )

        response = self._change_password()
        self._check_success_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_SUCCESS",
            msg=SecurityMsg.change_password_success,
        )

    def test_change_passwd_no_data(self) -> None:
        response = self._change_password(data1={})
        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            error={"new_password": ["Missing data for required field."]},
        )

    def test_change_passwd_empty_data(self) -> None:
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.CHANGE_PW_AUTHN,
        )

        data1 = {"new_password": "", "old_password": ""}
        response = self._change_password(data1=data1)
        self._check_error_response(
            response, type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL", msg=SecurityMsg.chpass_no_data
        )

    @patch("eduid.webapp.security.views.change_password.change_password")
    def test_change_passwd_no_csrf(self, mock_change_password: MagicMock) -> None:
        mock_change_password.return_value = True

        data1 = {"csrf_token": ""}
        response = self._change_password(data1=data1)
        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    @patch("eduid.webapp.security.views.change_password.change_password")
    def test_change_passwd_wrong_csrf(self, mock_change_password: MagicMock) -> None:
        mock_change_password.return_value = True

        data1 = {"csrf_token": "wrong-token"}
        response = self._change_password(data1=data1)
        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    @patch("eduid.webapp.security.views.change_password.change_password")
    def test_change_passwd_weak(self, mock_change_password: MagicMock) -> None:
        mock_change_password.return_value = True

        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.CHANGE_PW_AUTHN,
        )

        data1 = {"new_password": "pw"}
        response = self._change_password(data1=data1)
        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            msg=SecurityMsg.chpass_weak,
        )

    def test_change_passwd_no_reauthn(self) -> None:
        response = self._change_password()
        self._check_must_authenticate_response(
            response=response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            frontend_action=FrontendAction.CHANGE_PW_AUTHN,
            authn_status=AuthnActionStatus.NOT_FOUND,
        )

    def test_get_suggested_and_change(self) -> None:
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.CHANGE_PW_AUTHN,
        )

        response = self._get_suggested_and_change()
        self._check_success_response(
            response=response, type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_SUCCESS"
        )

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        password = user.credentials.to_list()[-1]
        assert isinstance(password, Password)
        self.assertTrue(password.is_generated)

    def test_get_suggested_and_change_custom(self) -> None:
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.CHANGE_PW_AUTHN,
        )

        data1 = {"new_password": "0ieT/(.edW76"}
        response = self._get_suggested_and_change(data1=data1)
        self._check_success_response(
            response=response, type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_SUCCESS"
        )

        # check that the password is marked as generated in this case changed
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        password = user.credentials.to_list()[-1]
        assert isinstance(password, Password)
        self.assertFalse(password.is_generated)

    def test_get_suggested_and_change_wrong_csrf(self) -> None:
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.CHANGE_PW_AUTHN,
        )

        data1 = {"csrf_token": "wrong-token"}
        response = self._get_suggested_and_change(data1=data1)

        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

        # check that the password is not marked as generated, in this case changed
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        password = user.credentials.to_list()[-1]
        assert isinstance(password, Password)
        self.assertFalse(password.is_generated)

    def test_get_suggested_and_change_wrong_old_pw(self) -> None:
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.CHANGE_PW_AUTHN,
        )

        response = self._get_suggested_and_change(correct_old_password=False)
        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            msg=SecurityMsg.unrecognized_pw,
        )

        # check that the password is not marked as generated, in this case changed
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        password = user.credentials.to_list()[-1]
        assert isinstance(password, Password)
        self.assertFalse(password.is_generated)

    def test_get_suggested_and_change_weak_new_pw(self) -> None:
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.CHANGE_PW_AUTHN,
        )

        data1 = {"new_password": "pw"}
        response = self._get_suggested_and_change(data1=data1)
        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            msg=SecurityMsg.chpass_weak,
        )

        # check that the password is not marked as generated, in this case changed
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        password = user.credentials.to_list()[-1]
        assert isinstance(password, Password)
        self.assertFalse(password.is_generated)

    def test_get_suggested_and_change_no_old_password(self) -> None:
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.CHANGE_PW_AUTHN,
        )

        self.app.conf.chpass_old_password_needed = (
            False  # allow password change without the old password, rely on force authn
        )
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        assert len(user.credentials.filter(Password)) == 1
        self.request_user_sync(user)

        response = self._get_suggested_and_change(data1={"old_password": None}, correct_old_password=False)
        self._check_success_response(
            response=response, type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_SUCCESS"
        )

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.credentials.filter(Password)[-1].is_generated is True
        assert len(user.credentials.filter(Password)) == 1

    def test_get_suggested_and_change_pw_check_consumed(self) -> None:
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.CHANGE_PW_AUTHN,
        )

        self.app.conf.chpass_old_password_needed = (
            False  # allow password change without the old password, rely on force authn
        )

        # do a password change
        response = self._get_suggested_and_change(data1={"old_password": None}, correct_old_password=False)
        self._check_success_response(
            response=response, type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_SUCCESS"
        )
        # try to do another one while the previous one could be valid if not explicitly consumed
        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.app.test_request_context(), self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                data = {"csrf_token": sess.get_csrf_token(), "new_password": "new_password"}
            response2 = client.post(
                "/change-password/set-password",
                data=json.dumps(data),
                content_type=self.content_type_json,
            )
        self._check_must_authenticate_response(
            response=response2,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            frontend_action=FrontendAction.CHANGE_PW_AUTHN,
            authn_status=AuthnActionStatus.CONSUMED,
        )
