import json
from datetime import timedelta
from typing import Any, Mapping, Optional
from unittest.mock import patch
from uuid import uuid4

from eduid.userdb.credentials import Password
from eduid.userdb.element import ElementKey
from eduid.userdb.util import utc_now
from eduid.webapp.authn.views import FALLBACK_FRONTEND_ACTION
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.api.utils import hash_password
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.session.namespaces import AuthnParameters, AuthnRequestRef, SP_AuthnRequest
from eduid.webapp.security.app import SecurityApp, security_init_app
from eduid.webapp.security.helpers import SecurityMsg


class ChangePasswordTests(EduidAPITestCase[SecurityApp]):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self, *args: Any, **kwargs: Any):
        self.test_user_eppn = "hubba-bubba"
        self.test_user_email = "johnsmith@example.com"
        self.test_user_nin = "197801011235"
        super().setUp(*args, **kwargs, copy_user_to_private=True)

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

    def _get_suggested(self, reauthn: Optional[int] = 60):
        """
        GET a suggested password.
        """
        response = self.browser.get("/change-password/suggested-password")
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                if reauthn is not None:
                    # Add authn data faking a reauthn event has taken place for this action
                    _authn_id = AuthnRequestRef(str(uuid4()))
                    sess.authn.sp.authns[_authn_id] = SP_AuthnRequest(
                        post_authn_action=AuthnAcsAction.change_password,
                        redirect_url="/test",
                        authn_instant=utc_now() - timedelta(seconds=reauthn),
                        frontend_action=FALLBACK_FRONTEND_ACTION,
                    )
            return client.get("/change-password/suggested-password")

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _change_password(
        self,
        mock_request_user_sync: Any,
        data1: Optional[dict[str, Any]] = None,
        reauthn: Optional[int] = 60,
    ):
        """
        To change the password of the test user, POST old and new passwords,
        mocking the required re-authentication (by setting a flag in the session).

        :param data1: to control the data sent to the change-password endpoint.
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    if reauthn is not None:
                        # Add authn data faking a reauthn event has taken place for this action
                        _authn_id = AuthnRequestRef(str(uuid4()))
                        sess.authn.sp.authns[_authn_id] = SP_AuthnRequest(
                            post_authn_action=AuthnAcsAction.change_password,
                            redirect_url="/test",
                            authn_instant=utc_now() - timedelta(seconds=reauthn),
                            frontend_action=FALLBACK_FRONTEND_ACTION,
                            params=AuthnParameters(force_authn=True, same_user=True, high_security=True),
                        )
                    data = {"new_password": "0ieT/(.edW76", "old_password": "5678", "csrf_token": sess.get_csrf_token()}
                    if data1 == {}:
                        data = {"csrf_token": sess.get_csrf_token()}
                    elif data1 is not None:
                        data.update(data1)

                return client.post(
                    "/change-password/set-password", data=json.dumps(data), content_type=self.content_type_json
                )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _get_suggested_and_change(
        self,
        mock_request_user_sync: Any,
        data1: Optional[dict[str, Any]] = None,
        correct_old_password: bool = True,
        reauthn: Optional[int] = 60,
    ):
        """
        To change the password of the test user using a suggested password,
        first GET a suggested password, and then POST old and new passwords,
        mocking the required re-authentication (by setting a flag in the session).

        :param data1: to control the data sent to the change-password endpoint.
        :param correct_old_password: mock result for authentication with old password
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with patch("eduid.webapp.common.authn.vccs.VCCSClient.add_credentials", return_value=True):
                    with patch("eduid.webapp.common.authn.vccs.VCCSClient.revoke_credentials", return_value=True):
                        with patch(
                            "eduid.webapp.common.authn.vccs.VCCSClient.authenticate", return_value=correct_old_password
                        ):
                            if reauthn is not None:
                                # Add authn data faking a reauthn event has taken place for this action
                                with client.session_transaction() as sess:
                                    _authn_id = AuthnRequestRef(str(uuid4()))
                                    sess.authn.sp.authns[_authn_id] = SP_AuthnRequest(
                                        post_authn_action=AuthnAcsAction.change_password,
                                        redirect_url="/test",
                                        authn_instant=utc_now() - timedelta(seconds=reauthn),
                                        credentials_used=[ElementKey("112345678901234567890123")],
                                        frontend_action=FALLBACK_FRONTEND_ACTION,
                                        params=AuthnParameters(force_authn=True, same_user=True, high_security=True),
                                    )
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
    def test_user_setup(self):
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    def test_app_starts(self):
        self.assertEqual(self.app.conf.app_name, "testing")
        response1 = self.browser.get("/change-password/suggested-password")
        assert response1.status_code == 302  # redirect to the login page
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            response2 = client.get("/change-password/suggested-password")
            assert response2.status_code == 200  # authenticated response

    def test_get_suggested(self):
        response = self._get_suggested()
        passwd = json.loads(response.data)
        self.assertEqual(passwd["type"], "GET_CHANGE_PASSWORD_CHANGE_PASSWORD_SUGGESTED_PASSWORD_SUCCESS")

    @patch("eduid.webapp.security.views.change_password.change_password")
    def test_change_passwd(self, mock_change_password):
        mock_change_password.return_value = True

        response = self._change_password()
        self._check_success_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_SUCCESS",
            msg=SecurityMsg.change_password_success,
        )

    def test_change_passwd_no_data(self):
        response = self._change_password(data1={})
        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            error={"new_password": ["Missing data for required field."]},
        )

    def test_change_passwd_empty_data(self):
        data1 = {"new_password": "", "old_password": ""}
        response = self._change_password(data1=data1)
        self._check_error_response(
            response, type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL", msg=SecurityMsg.chpass_no_data
        )

    @patch("eduid.webapp.security.views.change_password.change_password")
    def test_change_passwd_no_csrf(self, mock_change_password):
        mock_change_password.return_value = True

        data1 = {"csrf_token": ""}
        response = self._change_password(data1=data1)
        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    @patch("eduid.webapp.security.views.change_password.change_password")
    def test_change_passwd_wrong_csrf(self, mock_change_password):
        mock_change_password.return_value = True

        data1 = {"csrf_token": "wrong-token"}
        response = self._change_password(data1=data1)
        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    @patch("eduid.webapp.security.views.change_password.change_password")
    def test_change_passwd_weak(self, mock_change_password):
        mock_change_password.return_value = True

        data1 = {"new_password": "pw"}
        response = self._change_password(data1=data1)
        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            msg=SecurityMsg.chpass_weak,
        )

    def test_change_passwd_no_reauthn(self):
        response = self._change_password(reauthn=None)
        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            msg=SecurityMsg.no_reauthn,
        )

    def test_get_suggested_and_change(self):
        response = self._get_suggested_and_change()
        self._check_success_response(
            response=response, type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_SUCCESS"
        )

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertTrue(user.credentials.to_list()[-1].is_generated)

    def test_get_suggested_and_change_custom(self):
        data1 = {"new_password": "0ieT/(.edW76"}
        response = self._get_suggested_and_change(data1=data1)
        self._check_success_response(
            response=response, type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_SUCCESS"
        )

        # check that the password is marked as generated in this case changed
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    def test_get_suggested_and_change_wrong_csrf(self):
        data1 = {"csrf_token": "wrong-token"}
        response = self._get_suggested_and_change(data1=data1)

        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

        # check that the password is not marked as generated, in this case changed
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    def test_get_suggested_and_change_wrong_old_pw(self):
        response = self._get_suggested_and_change(correct_old_password=False)
        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            msg=SecurityMsg.unrecognized_pw,
        )

        # check that the password is not marked as generated, in this case changed
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    def test_get_suggested_and_change_weak_new_pw(self):
        data1 = {"new_password": "pw"}
        response = self._get_suggested_and_change(data1=data1)
        self._check_error_response(
            response,
            type_="POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SET_PASSWORD_FAIL",
            msg=SecurityMsg.chpass_weak,
        )

        # check that the password is not marked as generated, in this case changed
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    def test_get_suggested_and_change_no_old_password(self):
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
