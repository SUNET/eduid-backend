import datetime
import json
from collections.abc import Mapping
from typing import Any
from unittest.mock import Mock, patch
from urllib.parse import quote_plus

from flask import url_for
from werkzeug.test import TestResponse

from eduid.common.config.base import EduidEnvironment
from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials import Password, Webauthn
from eduid.userdb.exceptions import UserHasNotCompletedSignup
from eduid.userdb.fixtures.fido_credentials import webauthn_credential
from eduid.userdb.fixtures.fido_credentials import webauthn_credential as sample_credential
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.reset_password import ResetPasswordEmailAndPhoneState, ResetPasswordEmailState
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.api.utils import get_zxcvbn_terms, hash_password
from eduid.webapp.common.authn.testing import TestVCCSClient
from eduid.webapp.common.authn.tests.test_fido_tokens import (
    SAMPLE_WEBAUTHN_APP_CONFIG,
    SAMPLE_WEBAUTHN_FIDO2STATE,
    SAMPLE_WEBAUTHN_REQUEST,
)
from eduid.webapp.common.session.namespaces import MfaAction, WebauthnState
from eduid.webapp.reset_password.app import ResetPasswordApp, init_reset_password_app
from eduid.webapp.reset_password.helpers import (
    ResetPwMsg,
    generate_suggested_password,
    get_extra_security_alternatives,
    send_verify_phone_code,
)

__author__ = "eperez"


class ResetPasswordTests(EduidAPITestCase[ResetPasswordApp]):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        self.other_test_user = UserFixtures().mocked_user_standard_2

    def load_app(self, config: Mapping[str, Any] | None) -> ResetPasswordApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_reset_password_app(test_config=config)

    def update_config(self, config: dict[str, Any]):
        config.update(
            {
                "available_languages": {"en": "English", "sv": "Svenska"},
                "vccs_url": "http://vccs",
                "email_code_timeout": 7200,
                "phone_code_timeout": 600,
                "password_entropy": 25,
                "dashboard_url": "https://dashboard.dev.eduid.se",
            }
        )
        config.update(SAMPLE_WEBAUTHN_APP_CONFIG)
        return config

    # Parameterized test methods

    def _post_email_address(
        self,
        data1: dict[str, Any] | None = None,
    ):
        """
        POST an email address to start the reset password process for the corresponding account.

        :param data1: to control the data sent with the POST request.
        """
        if self.test_user.mail_addresses.primary is None:
            raise RuntimeError(f"user {self.test_user} has no primary email address")

        with self.session_cookie_anon(self.browser) as c:
            # TODO: GET a csrf token, this should be a call to jsconfig
            response = c.get("/", content_type=self.content_type_json)
            data = {
                "email": self.test_user.mail_addresses.primary.email,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
            }
            if data1 is not None:
                data.update(data1)

            response = c.post("/", data=json.dumps(data), content_type=self.content_type_json)
            self.assertEqual(200, response.status_code)
            return response

    def _post_reset_code(
        self, data1: dict[str, Any] | None = None, data2: dict[str, Any] | None = None
    ) -> TestResponse | None:
        """
        Create a password rest state for the test user, grab the created verification code from the db,
        and use it to get configuration for the reset form.

        :param data1: to control the data (email) sent to create the reset state
        :param data2: to control the data (verification code) used to get the configuration.
        """
        response = self._post_email_address(data1=data1)
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        if not state:
            return None

        with self.app.test_request_context():
            url = url_for("reset_password.verify_email", _external=True)

        with self.session_cookie_anon(self.browser) as c:
            data = {
                "email_code": state.email_code.code,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
            }
            if data2 is not None:
                data.update(data2)
            return c.post(url, data=json.dumps(data), content_type=self.content_type_json)

    @patch("eduid.webapp.common.authn.vccs.get_vccs_client")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _post_reset_password(
        self,
        mock_request_user_sync: Any,
        mock_get_vccs_client: Any,
        data1: dict[str, Any] | None = None,
        data2: dict[str, Any] | None = None,
    ):
        """
        Test sending data from the reset password form, without extra security.
        First POST an email address to the / endpoint to create a reset password state,
        and then POST data to the endpoint to actually reset the password.

        :param data1: control the data sent to the / endpoint (an email address)
        :param data2: control the data sent to actually reset the password.
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_get_vccs_client.return_value = TestVCCSClient()

        # check that the user has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        self.assertEqual(len(verified_phone_numbers), 1)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True

        response = self._post_email_address(data1=data1)
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(state, ResetPasswordEmailState)

        with self.app.test_request_context():
            url = url_for("reset_password.set_new_pw_no_extra_security", _external=True)

        with self.session_cookie_anon(self.browser) as c:
            # Make sure we know the password in the session
            new_password = generate_suggested_password(self.app.conf.password_length)
            with c.session_transaction() as sess:
                sess.reset_password.generated_password_hash = hash_password(new_password)

            data = {
                "email_code": state.email_code.code,
                "password": new_password,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
            }
            if data2 == {}:
                data = {}
            elif data2 is not None:
                data.update(data2)

            return c.post(url, data=json.dumps(data), content_type=self.content_type_json)

    @patch("eduid.webapp.common.authn.vccs.get_vccs_client")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms")
    def _post_choose_extra_sec(
        self,
        mock_sendsms: Any,
        mock_request_user_sync: Any,
        mock_get_vccs_client: Any,
        sendsms_side_effect: Any = None,
        data1: dict[str, Any] | None = None,
        data2: dict[str, Any] | None = None,
        data3: dict[str, Any] | None = None,
        repeat: bool = False,
    ):
        """
        Test choosing extra security via a confirmed phone number to reset the password.
        First create the reset password state in the database, then POST the generated code
        to get the configuration for the reset password form, and finally POST the code and
        an index selecting the phone number to use for extra security.

        :param data1: to control what email is sent to create the state and start the process
        :param data2: to control the code sent to obtain configuration for the reset form
        :param data3: to control what data is sent (what confirmed pone number is chosen) to send
                      an SMS with an extra security verification code.
        :param repeat: if True, try to trigger sending the SMS twice.
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True
        if sendsms_side_effect:
            mock_sendsms.side_effect = sendsms_side_effect

        response = self._post_email_address(data1=data1)
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(state, ResetPasswordEmailState)

        with self.app.test_request_context():
            conf_url = url_for("reset_password.verify_email", _external=True)
            extra_security_phone_url = url_for("reset_password.choose_extra_security_phone", _external=True)

        with self.session_cookie_anon(self.browser) as c:
            data = {
                "email_code": state.email_code.code,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
            }
            if data2 is not None:
                data.update(data2)
            response = c.post(conf_url, data=json.dumps(data), content_type=self.content_type_json)
            self.assertEqual(200, response.status_code)

        with self.session_cookie_anon(self.browser) as c:
            data = {
                "csrf_token": self.get_response_payload(response)["csrf_token"],
                "email_code": state.email_code.code,
                "phone_index": "0",
            }
            if data3 is not None:
                data.update(data3)

            response = c.post(extra_security_phone_url, data=json.dumps(data), content_type=self.content_type_json)
            if repeat:
                response = c.post(extra_security_phone_url, data=json.dumps(data), content_type=self.content_type_json)
            return response

    @patch("eduid.webapp.common.authn.vccs.get_vccs_client")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms")
    def _post_reset_password_secure_phone(
        self,
        mock_sendsms: Any,
        mock_request_user_sync: Any,
        mock_get_vccs_client: Any,
        data1: dict[str, Any] | None = None,
        data2: dict[str, Any] | None = None,
    ):
        """
        Test fully resetting the password with extra security via a verification code sent by SMS.
        First initialize the reset password state by POSTing an email to the initial endpoint,
        then retrieve the state form the db and modify it in the way that choosing extra security
        with a verified phone number would, and finally POST the verification codes and
        the new password to finally reset the password.

        :param data1: To control the email sent to initiate the process
        :param data2: To control the data sent to actually finally reset the password.
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True

        response = self._post_email_address(data1=data1)
        state1 = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(state1, ResetPasswordEmailState)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        alternatives = get_extra_security_alternatives(user)
        state1.extra_security = alternatives
        state1.email_code.is_verified = True
        self.app.password_reset_state_db.save(state1)

        phone_number = state1.extra_security["phone_numbers"][0]
        with self.app.test_request_context():
            send_verify_phone_code(state1, phone_number["number"])
            url = url_for("reset_password.set_new_pw_extra_security_phone", _external=True)

        state2 = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(state2, ResetPasswordEmailAndPhoneState)

        with self.session_cookie_anon(self.browser) as c:
            new_password = generate_suggested_password(self.app.conf.password_length)
            with c.session_transaction() as sess:
                sess.reset_password.generated_password_hash = hash_password(new_password)
            data = {
                "csrf_token": self.get_response_payload(response)["csrf_token"],
                "email_code": state2.email_code.code,
                "phone_code": state2.phone_code.code,
                "password": new_password,
            }
            if data2 is not None:
                data.update(data2)

        return c.post(url, data=json.dumps(data), content_type=self.content_type_json)

    @patch("eduid.webapp.common.authn.vccs.get_vccs_client")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("fido2.cose.ES256.verify")
    def _post_reset_password_secure_token(
        self,
        mock_verify: Any,
        mock_request_user_sync: Any,
        mock_get_vccs_client: Any,
        data1: dict[str, Any] | None = None,
        credential_data: dict[str, Any] | None = None,
        data2: dict[str, Any] | None = None,
        fido2state: WebauthnState | None = None,
        custom_password: str | None = None,
    ):
        """
        Test resetting the password with extra security via a fido token.
        First create the reset password state in the database, then add a webauthn
        credential to the test user, then get the state from the db and modify it
        as if the user had chosen extra security via the webauthn token,
        and finally send the necessary data to actually reset the password.

        :param data1: to control what email is sent to create the state and start the process
        :param credential_data: to control the data set as webauthn credential on the test user
        :param data2: to control the data POSTed to finally reset the password
        :param fido2state: to control the fido state kept in the session
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_verify.return_value = True

        credential = sample_credential.to_dict()
        if credential_data:
            credential.update(credential_data)
        webauthn_credential = Webauthn.from_dict(credential)
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        user.credentials.add(webauthn_credential)
        self.app.central_userdb.save(user)

        response = self._post_email_address(data1=data1)
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(state, ResetPasswordEmailState)

        with self.app.test_request_context():
            state.extra_security = get_extra_security_alternatives(user)
        state.email_code.is_verified = True
        self.app.password_reset_state_db.save(state)

        if fido2state is None:
            fido2state = SAMPLE_WEBAUTHN_FIDO2STATE

        with self.app.test_request_context():
            url = url_for("reset_password.set_new_pw_extra_security_token", _external=True)

        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                sess.mfa_action.webauthn_state = fido2state
                new_password = generate_suggested_password(self.app.conf.password_length)
                sess.reset_password.generated_password_hash = hash_password(new_password)
            data = {
                "email_code": state.email_code.code,
                "password": custom_password or new_password,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
            }
            data.update(SAMPLE_WEBAUTHN_REQUEST)
            if data2 == {}:
                data = {}
            elif data2 is not None:
                data.update(data2)

        return c.post(url, data=json.dumps(data), content_type=self.content_type_json)

    @patch("eduid.webapp.common.authn.vccs.get_vccs_client")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _post_reset_password_secure_external_mfa(
        self,
        mock_request_user_sync: Any,
        mock_get_vccs_client: Any,
        data1: dict[str, Any] | None = None,
        data2: dict[str, Any] | None = None,
        external_mfa_state: dict[str, Any] | None = None,
        custom_password: str | None = None,
    ):
        """
        Test resetting the password with extra security via a external MFA.

        :param data1: to control what email is sent to create the state and start the process
        :param data2: to control the data POSTed to finally reset the password
        :param external_mfa_state: to control the external mfa state kept in the session
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_get_vccs_client.return_value = TestVCCSClient()

        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)

        response = self._post_email_address(data1=data1)
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(state, ResetPasswordEmailState)

        with self.app.test_request_context():
            state.extra_security = get_extra_security_alternatives(user)
        state.email_code.is_verified = True
        self.app.password_reset_state_db.save(state)

        with self.app.test_request_context():
            url = url_for("reset_password.set_new_pw_extra_security_external_mfa", _external=True)

        if external_mfa_state is not None:
            mfa_action = MfaAction(**external_mfa_state)
        else:
            mfa_action = MfaAction(
                success=True,
                issuer="Test external MFA issuer",
                authn_instant=str(utc_now().timestamp()),
                authn_context="test authn context",
            )

        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                sess._namespaces.mfa_action = mfa_action
                new_password = generate_suggested_password(self.app.conf.password_length)
                sess.reset_password.generated_password_hash = hash_password(new_password)
            data = {
                "email_code": state.email_code.code,
                "password": custom_password or new_password,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
            }
            if data2 == {}:
                data = {}
            elif data2 is not None:
                data.update(data2)

        return c.post(url, data=json.dumps(data), content_type=self.content_type_json)

    def _get_email_code_backdoor(self, data1: dict[str, Any] | None = None, magic_cookie_name: str | None = None):
        """
        Create a password rest state for the test user, grab the created verification code from the db,
        and use it to get configuration for the reset form.

        :param data1: to control the data (email) sent to create the reset state
        """
        self._post_email_address(data1=data1)
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(state, ResetPasswordEmailState)

        with self.session_cookie_and_magic_cookie_anon(self.browser, magic_cookie_name=magic_cookie_name) as client:
            eppn = quote_plus(self.test_user.eppn)
            return client.get(f"/get-email-code?eppn={eppn}")

    @patch("eduid.webapp.common.authn.vccs.get_vccs_client")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms")
    def _get_phone_code_backdoor(
        self,
        mock_sendsms: Any,
        mock_request_user_sync: Any,
        mock_get_vccs_client: Any,
        sendsms_side_effect: Any = None,
        magic_cookie_name: str | None = None,
    ):
        """
        Test choosing extra security via a confirmed phone number to reset the password,
        and getting the generated phone verification code through the backdoor
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True
        if sendsms_side_effect:
            mock_sendsms.side_effect = sendsms_side_effect

        response = self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(state, ResetPasswordEmailState)

        with self.app.test_request_context():
            config_url = url_for("reset_password.verify_email", _external=True)
            extra_security_phone_url = url_for("reset_password.choose_extra_security_phone", _external=True)

        with self.session_cookie_anon(self.browser) as client:
            data = {
                "email_code": state.email_code.code,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
            }
            response = client.post(config_url, data=json.dumps(data), content_type=self.content_type_json)
            self.assertEqual(200, response.status_code)

        with self.session_cookie_and_magic_cookie_anon(self.browser, magic_cookie_name=magic_cookie_name) as client:
            data = {
                "csrf_token": self.get_response_payload(response)["csrf_token"],
                "email_code": state.email_code.code,
                "phone_index": "0",
            }
            response = client.post(extra_security_phone_url, data=json.dumps(data), content_type=self.content_type_json)
            self.assertEqual(200, response.status_code)

            eppn = quote_plus(self.test_user.eppn)

            return client.get(f"/get-phone-code?eppn={eppn}")

    # actual tests
    def test_correct_user_setup(self):
        # Check that user has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        self.assertEqual(1, len(verified_phone_numbers))
        verified_identities = user.identities.verified
        self.assertEqual(3, len(verified_identities))

    def test_get_zxcvbn_terms(self):
        with self.app.test_request_context():
            terms = get_zxcvbn_terms(self.test_user)
            self.assertEqual(["John", "Smith", "johnsmith", "johnsmith2"], terms)

    def test_get_zxcvbn_terms_no_given_name(self):
        with self.app.test_request_context():
            self.test_user.given_name = ""
            self.app.central_userdb.save(self.test_user)
            terms = get_zxcvbn_terms(self.test_user)
            self.assertEqual(["Smith", "johnsmith", "johnsmith2"], terms)

    def test_get_zxcvbn_terms_no_surname(self):
        with self.app.test_request_context():
            self.test_user.surname = ""
            self.app.central_userdb.save(self.test_user)
            terms = get_zxcvbn_terms(self.test_user)
            self.assertEqual(["John", "johnsmith", "johnsmith2"], terms)

    def test_app_starts(self):
        self.assertEqual("reset_password", self.app.conf.app_name)

    def test_post_email_address(self):
        response = self._post_email_address()
        self._check_success_response(response, msg=ResetPwMsg.reset_pw_initialized, type_="POST_RESET_PASSWORD_SUCCESS")
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        self.assertEqual(state.email_address, "johnsmith@example.com")

    def test_post_email_address_throttled(self):
        response1 = self._post_email_address()
        self._check_success_response(
            response1, msg=ResetPwMsg.reset_pw_initialized, type_="POST_RESET_PASSWORD_SUCCESS"
        )
        response2 = self._post_email_address()
        self._check_success_response(
            response2,
            msg=ResetPwMsg.email_send_throttled,
            type_="POST_RESET_PASSWORD_SUCCESS",
            payload={"throttled_max": 300},
        )

    def test_do_not_overwrite_email_state(self):
        # Avoid getting throttled
        self.app.conf.throttle_resend = datetime.timedelta()
        response1 = self._post_email_address()
        self._check_success_response(
            response1, msg=ResetPwMsg.reset_pw_initialized, type_="POST_RESET_PASSWORD_SUCCESS"
        )
        state1 = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        self.assertEqual(state1.email_address, "johnsmith@example.com")
        self.assertIsNotNone(state1.email_code.code)

        response2 = self._post_email_address()
        self._check_success_response(
            response2, msg=ResetPwMsg.reset_pw_initialized, type_="POST_RESET_PASSWORD_SUCCESS"
        )
        state2 = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        self.assertEqual(state1.email_code.code, state2.email_code.code)

    def test_overwrite_expired_email_state(self):
        response1 = self._post_email_address()
        self._check_success_response(
            response1, msg=ResetPwMsg.reset_pw_initialized, type_="POST_RESET_PASSWORD_SUCCESS"
        )
        state1 = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        # Set created time 5 minutes before email_code_timeout
        state1.email_code.created_ts = datetime.datetime.utcnow() - (
            self.app.conf.email_code_timeout + datetime.timedelta(minutes=5)
        )
        self.app.password_reset_state_db.save(state1)

        response2 = self._post_email_address()
        self._check_success_response(
            response2, msg=ResetPwMsg.reset_pw_initialized, type_="POST_RESET_PASSWORD_SUCCESS"
        )
        state2 = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        self.assertNotEqual(state1.email_code.code, state2.email_code.code)

    @patch("eduid.userdb.userdb.UserDB.get_user_by_mail")
    def test_post_email_uncomplete_signup(self, mock_get_user: Mock):
        mock_get_user.side_effect = UserHasNotCompletedSignup("incomplete signup")
        response = self._post_email_address()
        self._check_error_response(response, msg=ResetPwMsg.invalid_user, type_="POST_RESET_PASSWORD_FAIL")

    def test_post_unknown_email_address(self):
        data = {"email": "unknown@unplaced.un"}
        response = self._post_email_address(data1=data)
        self._check_error_response(response, msg=ResetPwMsg.user_not_found, type_="POST_RESET_PASSWORD_FAIL")

    def test_post_invalid_email_address(self):
        data = {"email": "invalid-address"}
        response = self._post_email_address(data1=data)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_FAIL",
            payload={"error": {"email": ["Not a valid email address."]}},
        )

    def test_post_reset_code(self):
        response = self._post_reset_code()
        assert response is not None
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_VERIFY_EMAIL_SUCCESS",
            payload={
                "email_address": "johnsmith@example.com",
                "extra_security": {"external_mfa": True, "phone_numbers": [{"index": 0, "number": "XXXXXXXXXX09"}]},
                "success": True,
                "zxcvbn_terms": ["John", "Smith", "johnsmith", "johnsmith2"],
            },
        )

    def test_post_reset_code_unknown_email(self):
        data1 = {"email": "unknown@unknown.com"}
        assert not self._post_reset_code(data1=data1)

    def test_post_reset_code_no_extra_sec(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        # Remove all verified phone numbers
        for number in user.phone_numbers.verified:
            user.phone_numbers.remove_handling_primary(number.key)
        # Remove all verified identities
        for identity in user.identities.verified:
            user.identities.remove(identity.key)
        self.app.central_userdb.save(user)
        response = self._post_reset_code()
        assert response is not None
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_VERIFY_EMAIL_SUCCESS",
            payload={
                "email_address": "johnsmith@example.com",
                "extra_security": {},
                "success": True,
                "zxcvbn_terms": ["John", "Smith", "johnsmith", "johnsmith2"],
            },
        )

    def test_post_reset_code_extra_security_alternatives_security_key(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        # add security key to user
        user.credentials.add(webauthn_credential)
        self.app.central_userdb.save(user)
        response = self._post_reset_code()
        assert response is not None
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_VERIFY_EMAIL_SUCCESS",
            payload={
                "email_address": "johnsmith@example.com",
                "success": True,
                "zxcvbn_terms": ["John", "Smith", "johnsmith", "johnsmith2"],
            },
        )
        # cant compare extra_security with _check_success_response as the value of webauthn_options is different per run
        assert "tokens" in self.get_response_payload(response)["extra_security"]
        assert "webauthn_options" in self.get_response_payload(response)["extra_security"]["tokens"]

    def test_post_reset_wrong_code(self):
        data2 = {"email_code": "wrong-code"}
        response = self._post_reset_code(data2=data2)
        assert response is not None
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.state_not_found
        )

    def test_post_reset_wrong_csrf(self):
        data2 = {"csrf_token": "wrong-code"}
        response = self._post_reset_code(data2=data2)
        assert response is not None
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    def test_post_reset_invalid_session_eppn(self):
        if self.test_user.mail_addresses.primary is None:
            raise RuntimeError(f"user {self.test_user} has no primary email address")

        # Request reset password email for test_user using other_test_user session
        with self.app.test_request_context():
            request_url = url_for("reset_password.start_reset_pw", _external=True)
        with self.session_cookie(self.browser, eppn=self.other_test_user.eppn) as c:
            response = c.get("/", content_type=self.content_type_json)
            data = {
                "email": self.test_user.mail_addresses.primary.email,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
            }
            response = c.post(request_url, data=json.dumps(data), content_type=self.content_type_json)

        # Try to verify email code for test_user using other_test_user session
        with self.app.test_request_context():
            verify_url = url_for("reset_password.verify_email", _external=True)
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        with self.session_cookie(self.browser, eppn=self.other_test_user.eppn) as c:
            data = {
                "email_code": state.email_code.code,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
            }
            response = c.post(verify_url, data=json.dumps(data), content_type=self.content_type_json)

        self._check_error_response(
            response=response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.invalid_session
        )

    def test_post_reset_password(self):
        response = self._post_reset_password()
        self._check_success_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_SUCCESS", msg=ResetPwMsg.pw_reset_success
        )

        # check that the user no longer has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        self.assertEqual(len(verified_phone_numbers), 0)
        verified_identities = user.identities.verified
        self.assertEqual(len(verified_identities), 0)

        # check that the password is marked as generated
        self.assertTrue(user.credentials.to_list()[0].is_generated)

    def test_post_reset_password_no_data(self):
        response = self._post_reset_password(data2={})
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_FAIL",
            error={
                "email_code": ["Missing data for required field."],
                "csrf_token": ["Missing data for required field."],
                "password": ["Missing data for required field."],
            },
        )

    def test_post_reset_password_weak(self):
        data2 = {"password": "pw"}
        response = self._post_reset_password(data2=data2)
        self._check_error_response(response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_FAIL", msg=ResetPwMsg.resetpw_weak)

    def test_post_reset_password_no_csrf(self):
        data2 = {"csrf_token": ""}
        response = self._post_reset_password(data2=data2)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_FAIL",
            error={
                "csrf_token": ["CSRF failed to validate"],
            },
        )

    def test_post_reset_password_wrong_code(self):
        data2 = {"email_code": "wrong-code"}
        response = self._post_reset_password(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_FAIL", msg=ResetPwMsg.state_not_found
        )

        # check that the user still has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        self.assertEqual(len(verified_phone_numbers), 1)
        verified_identities = user.identities.verified
        self.assertEqual(len(verified_identities), 3)

    def test_post_reset_password_custom(self):
        data2 = {"password": "cust0m-p4ssw0rd"}
        response = self._post_reset_password(data2=data2)
        self._check_success_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_SUCCESS", msg=ResetPwMsg.pw_reset_success
        )

        user = self.app.private_userdb.get_user_by_eppn(self.test_user.eppn)
        self.assertFalse(user.credentials.to_list()[0].is_generated)

    def test_post_choose_extra_sec(self):
        response = self._post_choose_extra_sec()
        self._check_success_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_SUCCESS", msg=ResetPwMsg.send_sms_success
        )

    def test_post_choose_extra_sec_sms_fail(self):
        self.app.conf.throttle_sms = 300
        from eduid.common.rpc.exceptions import MsgTaskFailed

        response = self._post_choose_extra_sec(sendsms_side_effect=MsgTaskFailed())
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.send_sms_failure
        )

    def test_post_choose_extra_sec_throttled(self):
        self.app.conf.throttle_sms = datetime.timedelta(minutes=5)
        response = self._post_choose_extra_sec(repeat=True)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.send_sms_throttled
        )

    def test_post_choose_extra_sec_not_throttled(self):
        self.app.conf.throttle_sms = 0
        response = self._post_choose_extra_sec(repeat=True)
        self._check_success_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_SUCCESS", msg=ResetPwMsg.send_sms_success
        )

    def test_post_choose_extra_sec_wrong_code(self):
        data2 = {"email_code": "wrong-code"}
        response = self._post_choose_extra_sec(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.email_not_validated
        )

    def test_post_choose_extra_sec_bad_phone_index(self):
        data3 = {"phone_index": "3"}
        response = self._post_choose_extra_sec(data3=data3)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.unknown_phone_number
        )

    def test_post_choose_extra_sec_wrong_csrf_token(self):
        data3 = {"csrf_token": "wrong-token"}
        response = self._post_choose_extra_sec(data3=data3)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    def test_post_choose_extra_sec_wrong_final_code(self):
        data3 = {"email_code": "wrong-code"}
        response = self._post_choose_extra_sec(data3=data3)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.state_not_found
        )

    def test_post_reset_password_secure_phone(self):
        response = self._post_reset_password_secure_phone()
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_SUCCESS",
            msg=ResetPwMsg.pw_reset_success,
        )

        # check that the user still has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        self.assertEqual(1, len(verified_phone_numbers))
        verified_identities = user.identities.verified
        self.assertEqual(len(verified_identities), 3)

    @patch("eduid.webapp.reset_password.views.reset_password.verify_phone_number")
    def test_post_reset_password_secure_phone_verify_fail(self, mock_verify: Any):
        mock_verify.return_value = False
        response = self._post_reset_password_secure_phone()
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.phone_invalid
        )

    def test_post_reset_password_secure_phone_wrong_csrf_token(self):
        data2 = {"csrf_token": "wrong-code"}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    def test_post_reset_password_secure_phone_wrong_email_code(self):
        data2 = {"email_code": "wrong-code"}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.state_not_found
        )

    def test_post_reset_password_secure_phone_wrong_sms_code(self):
        data2 = {"phone_code": "wrong-code"}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            msg=ResetPwMsg.unknown_phone_code,
        )

    def test_post_reset_password_secure_phone_weak_password(self):
        data2 = {"password": "pw"}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.resetpw_weak
        )

    def test_post_reset_password_secure_token(self):
        response = self._post_reset_password_secure_token()
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_SUCCESS",
            msg=ResetPwMsg.pw_reset_success,
        )

        # check that the user still has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        self.assertEqual(1, len(verified_phone_numbers))
        verified_identities = user.identities.verified
        self.assertEqual(len(verified_identities), 3)

    def test_post_reset_password_secure_token_custom_pw(self):
        response = self._post_reset_password_secure_token(custom_password="T%7j 8/tT a0=b")
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_SUCCESS",
            msg=ResetPwMsg.pw_reset_success,
        )
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        for cred in user.credentials.filter(Password):
            self.assertFalse(cred.is_generated)

    def test_post_reset_password_secure_token_no_data(self):
        response = self._post_reset_password_secure_token(data2={})
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_FAIL",
            error={
                "email_code": ["Missing data for required field."],
                "csrf_token": ["Missing data for required field."],
                "password": ["Missing data for required field."],
            },
        )

    def test_post_reset_password_secure_token_wrong_credential(self):
        credential_data = {
            "credential_data": "AAAAAAAAAAAAAAAAAAAAAABAi3KjBT0t5TPm693T0O0f4zyiwvdu9cY8BegCjiVvq_FS-ZmPcvXipFvHvD5CH6ZVRR3nsVsOla0Cad3fbtUA_aUBAgMmIAEhWCCiwDYGxl1LnRMqooWm0aRR9YbBG2LZ84BMNh_4rHkA9yJYIIujMrUOpGekbXjgMQ8M13ZsBD_cROSPB79eGz2Nw1ZE"
        }
        response = self._post_reset_password_secure_token(credential_data=credential_data)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_FAIL", msg=ResetPwMsg.fido_token_fail
        )

    def test_post_reset_password_secure_token_wrong_request(self):
        data2 = {"authenticatorData": "Wrong-authenticatorData----UMmBLDxB7n3apMPQAAAAAAA"}
        response = self._post_reset_password_secure_token(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_FAIL", msg=ResetPwMsg.fido_token_fail
        )

    def test_post_reset_password_secure_token_wrong_csrf(self):
        data2 = {"csrf_token": "wrong-code"}
        response = self._post_reset_password_secure_token(data2=data2)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    def test_post_reset_password_secure_token_wrong_code(self):
        data2 = {"email_code": "wrong-code"}
        response = self._post_reset_password_secure_token(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_FAIL", msg=ResetPwMsg.state_not_found
        )

    def test_post_reset_password_secure_token_weak_password(self):
        data2 = {"password": "pw"}
        response = self._post_reset_password_secure_token(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_FAIL", msg=ResetPwMsg.resetpw_weak
        )

    def test_post_reset_password_secure_external_mfa(self):
        response = self._post_reset_password_secure_external_mfa()
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_EXTERNAL_MFA_SUCCESS",
            msg=ResetPwMsg.pw_reset_success,
        )

        # check that the user still has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        self.assertEqual(1, len(verified_phone_numbers))
        verified_identities = user.identities.verified
        self.assertEqual(len(verified_identities), 3)

    def test_post_reset_password_secure_external_mfa_no_mfa_auth(self):
        external_mfa_state = {"success": False, "issuer": None}
        response = self._post_reset_password_secure_external_mfa(external_mfa_state=external_mfa_state)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_EXTERNAL_MFA_FAIL",
            msg=ResetPwMsg.external_mfa_fail,
        )

    def test_post_reset_password_secure_email_timeout(self):
        self.app.conf.email_code_timeout = 0
        response = self._post_reset_password_secure_phone()
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            msg=ResetPwMsg.expired_email_code,
        )

    def test_post_reset_password_secure_phone_timeout(self):
        self.app.conf.phone_code_timeout = 0
        response = self._post_reset_password_secure_phone()
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            msg=ResetPwMsg.expired_phone_code,
        )

    def test_post_reset_password_secure_phone_custom(self):
        data2 = {"password": "other-password"}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_SUCCESS",
            msg=ResetPwMsg.pw_reset_success,
        )

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user.eppn)
        self.assertFalse(user.credentials.to_list()[0].is_generated)

    def test_revoke_termination_on_password_reset(self):
        # mark user as terminated
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        user.terminated = utc_now()
        self.app.central_userdb.save(user)

        response = self._post_reset_password()
        self._check_success_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_SUCCESS", msg=ResetPwMsg.pw_reset_success
        )

        # check that the user no longer has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        assert user.terminated is None

    def test_get_code_backdoor(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        resp = self._get_email_code_backdoor()

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data, state.email_code.code.encode("ascii"))

    def test_get_code_no_backdoor_in_pro(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("production")

        resp = self._get_email_code_backdoor()

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured1(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = ""
        self.app.conf.environment = EduidEnvironment("dev")

        resp = self._get_email_code_backdoor(magic_cookie_name="wrong_name")

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured2(self):
        self.app.conf.magic_cookie = ""
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        resp = self._get_email_code_backdoor()

        self.assertEqual(resp.status_code, 400)

    def test_get_phone_code_backdoor(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        resp = self._get_phone_code_backdoor()

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data, state.phone_code.code.encode("ascii"))

    def test_get_phone_code_no_backdoor_in_pro(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("production")

        resp = self._get_phone_code_backdoor()

        self.assertEqual(resp.status_code, 400)

    def test_get_phone_code_no_backdoor_misconfigured1(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = ""
        self.app.conf.environment = EduidEnvironment("dev")

        resp = self._get_phone_code_backdoor(magic_cookie_name="wrong_name")

        self.assertEqual(resp.status_code, 400)

    def test_get_phone_code_no_backdoor_misconfigured2(self):
        self.app.conf.magic_cookie = ""
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        resp = self._get_phone_code_backdoor()

        self.assertEqual(resp.status_code, 400)
