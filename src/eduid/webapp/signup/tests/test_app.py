# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# Copyright (c) 2018-2019 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional

from flask import Response as FlaskResponse
from mock import patch

from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.signup import SignupUser
from eduid.webapp.common.api.messages import CommonMsg, TranslatableMsg
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.signup.app import SignupApp, signup_init_app
from eduid.webapp.signup.helpers import SignupMsg
from eduid.webapp.signup.verifications import ProofingLogFailure, send_verification_mail

logger = logging.getLogger(__name__)


class SignupState(Enum):
    S5_CAPTCHA = "captcha"
    S6_MAIL_SENT_NO_USER = "no_user_created"
    S7_VERIFY_LINK = "verify_link"


@dataclass
class SignupResult:
    url: str
    reached_state: SignupState
    response: FlaskResponse


class SignupTests(EduidAPITestCase):

    app: SignupApp

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs, copy_user_to_private=True)

    def load_app(self, config: Mapping[str, Any]) -> SignupApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return signup_init_app(name="signup", test_config=config)

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        config.update(
            {
                "available_languages": {"en": "English", "sv": "Svenska"},
                "signup_authn_url": "/services/authn/signup-authn",
                "signup_url": "https://localhost/",
                "dashboard_url": "https://localhost/",
                "development": "DEBUG",
                "application_root": "/",
                "log_level": "DEBUG",
                "password_length": 10,
                "vccs_url": "http://turq:13085/",
                "tou_version": "2018-v1",
                "tou_url": "https://localhost/get-tous",
                "default_finish_url": "https://www.eduid.se/",
                "recaptcha_public_key": "XXXX",
                "recaptcha_private_key": "XXXX",
                "students_link": "https://www.eduid.se/index.html",
                "technicians_link": "https://www.eduid.se/tekniker.html",
                "staff_link": "https://www.eduid.se/personal.html",
                "faq_link": "https://www.eduid.se/faq.html",
                "environment": "dev",
            }
        )
        return config

    # parameterized test methods

    @patch("eduid.webapp.signup.views.verify_recaptcha")
    @patch("eduid.common.rpc.mail_relay.MailRelay.sendmail")
    def _captcha_new(
        self,
        mock_sendmail: Any,
        mock_recaptcha: Any,
        captcha_data: Optional[Mapping[str, Any]] = None,
        email: str = "dummy@example.com",
        recaptcha_return_value: bool = True,
        add_magic_cookie: bool = False,
        expect_success: bool = True,
        expected_message: TranslatableMsg = SignupMsg.reg_new,
        expected_payload: Optional[Mapping[str, Any]] = None,
    ):
        """
        :param captcha_data: to control the data POSTed to the /trycaptcha endpoint
        :param email: the email to use for registration
        :param recaptcha_return_value: to mock captcha verification failure
        :param add_magic_cookie: add magic cookie to the trycaptcha request
        """
        mock_sendmail.return_value = True
        mock_recaptcha.return_value = recaptcha_return_value

        with self.session_cookie_anon(self.browser) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "email": email,
                        "recaptcha_response": "dummy",
                        "tou_accepted": True,
                        "csrf_token": sess.get_csrf_token(),
                    }
                if captcha_data is not None:
                    data.update(captcha_data)

                if add_magic_cookie:
                    client.set_cookie(
                        "localhost", key=self.app.conf.magic_cookie_name, value=self.app.conf.magic_cookie
                    )

                _trycaptcha = "/trycaptcha"

                logger.info(f"Making request to {_trycaptcha} with data:\n{data}")
                response = client.post("/trycaptcha", data=json.dumps(data), content_type=self.content_type_json)

                logger.info(f"Request to {_trycaptcha} result: {response}")

                if response.status_code != 200:
                    return SignupResult(url=_trycaptcha, reached_state=SignupState.S5_CAPTCHA, response=response)

                if expect_success:
                    if not expected_payload:
                        expected_payload = {"next": "new"}

                    self._check_api_response(
                        response,
                        status=200,
                        message=expected_message,
                        type_="POST_SIGNUP_TRYCAPTCHA_SUCCESS",
                        payload=expected_payload,
                    )
                else:
                    self._check_api_response(
                        response,
                        status=200,
                        message=expected_message,
                        type_="POST_SIGNUP_TRYCAPTCHA_FAIL",
                        payload=expected_payload,
                    )

                logger.info(f"Validated {_trycaptcha} response:\n{response.json}")

                return SignupResult(url=_trycaptcha, reached_state=SignupState.S5_CAPTCHA, response=response)

    @patch("eduid.webapp.signup.views.verify_recaptcha")
    @patch("eduid.common.rpc.mail_relay.MailRelay.sendmail")
    def _resend_email(
        self, mock_sendmail: Any, mock_recaptcha: Any, data1: Optional[dict] = None, email: str = "dummy@example.com"
    ):
        """
        Trigger re-sending an email with a verification code.

        :param data1: to control the data POSTed to the resend-verification endpoint
        :param email: what email address to use
        """
        mock_sendmail.return_value = True
        mock_recaptcha.return_value = True

        with self.session_cookie_anon(self.browser) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"email": email, "csrf_token": sess.get_csrf_token()}
                if data1 is not None:
                    data.update(data1)

            return client.post("/resend-verification", data=json.dumps(data), content_type=self.content_type_json)

    @patch("eduid.webapp.signup.views.verify_recaptcha")
    @patch("eduid.common.rpc.mail_relay.MailRelay.sendmail")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def _verify_code(
        self,
        mock_add_credentials: Any,
        mock_request_user_sync: Any,
        mock_sendmail: Any,
        mock_recaptcha: Any,
        code: str = "",
        email: str = "dummy@example.com",
    ):
        """
        Test the verification link sent by email

        :param code: the code to use
        :param email: the email address to use
        """
        mock_add_credentials.return_value = True
        mock_request_user_sync.return_value = True
        mock_sendmail.return_value = True
        mock_recaptcha.return_value = True
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction():
                with self.app.test_request_context():
                    # lower because we are purposefully calling it with a mixed case mail address in tests
                    send_verification_mail(email.lower())
                    signup_user = self.app.private_userdb.get_user_by_pending_mail_address(email)
                    if signup_user and signup_user.pending_mail_address:
                        code = code or signup_user.pending_mail_address.verification_code or ""

                    return client.get("/verify-link/" + code)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def _verify_code_after_captcha(
        self,
        mock_add_credentials: Any,
        mock_request_user_sync: Any,
        data1: Optional[dict] = None,
        email: str = "dummy@example.com",
        captcha_expect_success: bool = True,
        captcha_expected_message: TranslatableMsg = SignupMsg.reg_new,
        verify_expect_success: bool = True,
        verify_expected_message: Optional[TranslatableMsg] = None,
        verify_expected_payload: Optional[Mapping[str, Any]] = None,
    ) -> SignupResult:
        """
        Verify the pending account with an emailed verification code after creating the account by verifying the captcha.

        :param data1: to control the data sent to the trycaptcha endpoint
        :param email: what email address to use
        """
        mock_add_credentials.return_value = True
        mock_request_user_sync.return_value = True

        with self.session_cookie_anon(self.browser) as client:

            captcha_res = self._captcha_new(
                email=email,
                captcha_data=data1,
                expect_success=captcha_expect_success,
                expected_message=captcha_expected_message,
            )
            if not captcha_expect_success:
                return captcha_res

            signup_user = self.app.private_userdb.get_user_by_pending_mail_address(email)
            if not signup_user:
                return captcha_res

            assert signup_user.pending_mail_address is not None
            assert signup_user.pending_mail_address.email == email.lower()
            assert signup_user.pending_mail_address.verification_code is not None

            _verify_link_url = "/verify-link/" + signup_user.pending_mail_address.verification_code
            response2 = client.get(_verify_link_url)

            if verify_expect_success:
                if not verify_expected_payload:
                    verify_expected_payload = {
                        "dashboard_url": "/services/authn/signup-authn",
                        "email": email.lower(),
                        "status": "verified",
                    }

                self._check_api_response(
                    response2,
                    status=200,
                    message=verify_expected_message,
                    type_="GET_SIGNUP_VERIFY_LINK_SUCCESS",
                    payload=verify_expected_payload,
                )

                assert "password" in response2.json["payload"]
                _pw_no_spaces = "".join(response2.json["payload"]["password"].split())
                assert len(_pw_no_spaces) == self.app.conf.password_length

            else:
                self._check_api_response(
                    response2, status=200, message=verify_expected_message, type_="GET_SIGNUP_VERIFY_LINK_FAIL"
                )

            return SignupResult(url=_verify_link_url, reached_state=SignupState.S7_VERIFY_LINK, response=response2)

    @patch("eduid.webapp.signup.views.verify_recaptcha")
    @patch("eduid.common.rpc.mail_relay.MailRelay.sendmail")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def _get_code_backdoor(
        self,
        mock_add_credentials: Any,
        mock_request_user_sync: Any,
        mock_sendmail: Any,
        mock_recaptcha: Any,
        email: str,
    ):
        """
        Test getting the generated verification code through the backdoor
        """
        mock_add_credentials.return_value = True
        mock_request_user_sync.return_value = True
        mock_sendmail.return_value = True
        mock_recaptcha.return_value = True
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction():
                with self.app.test_request_context():
                    send_verification_mail(email)

                    client.set_cookie(
                        "localhost", key=self.app.conf.magic_cookie_name, value=self.app.conf.magic_cookie
                    )
                    return client.get(f"/get-code?email={email}")

    def test_get_code_backdoor(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = "dev"

        email = "johnsmith4@example.com"
        resp = self._get_code_backdoor(email=email)

        signup_user = self.app.private_userdb.get_user_by_pending_mail_address(email)

        self.assertEqual(signup_user.pending_mail_address.verification_code, resp.data.decode("ascii"))

    def test_get_code_no_backdoor_in_pro(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = "production"

        email = "johnsmith4@example.com"
        resp = self._get_code_backdoor(email=email)

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured1(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = ""
        self.app.conf.environment = "dev"

        email = "johnsmith4@example.com"
        resp = self._get_code_backdoor(email=email)

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured2(self):
        self.app.conf.magic_cookie = ""
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = "dev"

        email = "johnsmith4@example.com"
        resp = self._get_code_backdoor(email=email)

        self.assertEqual(resp.status_code, 400)

    # actual tests

    def test_captcha_new_user(self):
        res = self._captcha_new()
        assert res.reached_state == SignupState.S5_CAPTCHA

    def test_captcha_new_user_mixed_case(self):
        res = self._captcha_new(email="MixedCase@example.com")
        assert res.reached_state == SignupState.S5_CAPTCHA

        mixed_user: SignupUser = self.app.private_userdb.get_user_by_pending_mail_address("MixedCase@example.com")
        lower_user: SignupUser = self.app.private_userdb.get_user_by_pending_mail_address("mixedcase@example.com")
        assert mixed_user.eppn == lower_user.eppn
        assert mixed_user.pending_mail_address.email == lower_user.pending_mail_address.email

    def test_captcha_new_no_key(self):
        self.app.conf.recaptcha_public_key = ""
        res = self._captcha_new(
            email="JohnSmith@Example.com", expect_success=False, expected_message=SignupMsg.no_recaptcha
        )
        assert res.reached_state == SignupState.S5_CAPTCHA

    def test_captcha_new_wrong_csrf(self):
        data = {"csrf_token": "wrong-token"}
        res = self._captcha_new(captcha_data=data, expect_success=False, expected_message=None)
        assert res.response.json["payload"]["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_captcha_existing_user(self):
        res = self._captcha_new(
            email="johnsmith@example.com", expect_success=False, expected_message=SignupMsg.email_used
        )
        assert res.reached_state == SignupState.S5_CAPTCHA

    def test_captcha_existing_user_mixed_case(self):
        res = self._captcha_new(
            email="JohnSmith@Example.com", expect_success=False, expected_message=SignupMsg.email_used
        )
        assert res.reached_state == SignupState.S5_CAPTCHA

    def test_captcha_remove_existing_signup_user(self):
        res = self._captcha_new(email="johnsmith2@example.com", expected_message=SignupMsg.reg_new)
        assert res.reached_state == SignupState.S5_CAPTCHA

    def test_captcha_remove_existing_signup_user_mixed_case(self):
        res = self._captcha_new(email="JohnSmith2@Example.com", expected_message=SignupMsg.reg_new)
        assert res.reached_state == SignupState.S5_CAPTCHA

        mixed_user: SignupUser = self.app.private_userdb.get_user_by_pending_mail_address("JohnSmith2@example.com")
        lower_user: SignupUser = self.app.private_userdb.get_user_by_pending_mail_address("johnsmith2@Example.com")
        assert mixed_user.eppn == lower_user.eppn
        assert mixed_user.pending_mail_address.email == lower_user.pending_mail_address.email

    def test_captcha_fail(self):
        res = self._captcha_new(
            recaptcha_return_value=False, expect_success=False, expected_message=SignupMsg.no_recaptcha
        )
        assert res.reached_state == SignupState.S5_CAPTCHA

    def test_captcha_backdoor(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = "dev"

        res = self._captcha_new(
            recaptcha_return_value=False,
            add_magic_cookie=True,
            expect_success=True,
            expected_message=SignupMsg.reg_new,
        )
        assert res.reached_state == SignupState.S5_CAPTCHA

    def test_captcha_no_backdoor_in_pro(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = "production"
        res = self._captcha_new(
            recaptcha_return_value=False,
            add_magic_cookie=True,
            expect_success=False,
            expected_message=SignupMsg.no_recaptcha,
        )
        assert res.reached_state == SignupState.S5_CAPTCHA

    def test_captcha_no_backdoor_misconfigured1(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = ""
        self.app.conf.environment = "dev"
        res = self._captcha_new(
            recaptcha_return_value=False,
            add_magic_cookie=True,
            expect_success=False,
            expected_message=SignupMsg.no_recaptcha,
        )
        assert res.reached_state == SignupState.S5_CAPTCHA

    def test_captcha_no_backdoor_misconfigured2(self):
        self.app.conf.magic_cookie = ""
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = "dev"
        res = self._captcha_new(
            recaptcha_return_value=False,
            add_magic_cookie=True,
            expect_success=False,
            expected_message=SignupMsg.no_recaptcha,
        )
        assert res.reached_state == SignupState.S5_CAPTCHA

    def test_captcha_no_data_fail(self):
        with self.session_cookie_anon(self.browser) as client:
            response = client.post("/trycaptcha")
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertEqual(data["error"], True)
            self.assertEqual(data["type"], "POST_SIGNUP_TRYCAPTCHA_FAIL")
            self.assertIn("email", data["payload"]["error"])
            self.assertIn("csrf_token", data["payload"]["error"])
            self.assertIn("recaptcha_response", data["payload"]["error"])

    def test_verify_code(self):
        response = self._verify_code()

        data = json.loads(response.data)
        self.assertEqual(data["type"], "GET_SIGNUP_VERIFY_LINK_SUCCESS")
        self.assertEqual(data["payload"]["status"], "verified")

    def test_verify_code_mixed_case(self):
        response = self._verify_code(email="MixedCase@Example.com")
        data = json.loads(response.data)
        self.assertEqual(data["type"], "GET_SIGNUP_VERIFY_LINK_SUCCESS")
        self.assertEqual(data["payload"]["status"], "verified")
        mixed_user: SignupUser = self.app.private_userdb.get_user_by_mail("MixedCase@Example.com")
        lower_user: SignupUser = self.app.private_userdb.get_user_by_mail("mixedcase@example.com")
        assert mixed_user.eppn == lower_user.eppn
        assert mixed_user.mail_addresses.primary.email == lower_user.mail_addresses.primary.email

    def test_verify_code_unsynced(self):
        with patch("eduid.webapp.signup.helpers.save_and_sync_user") as mock_save:
            mock_save.side_effect = UserOutOfSync("unsync")
            response = self._verify_code()
            data = json.loads(response.data)
            self.assertEqual(data["type"], "GET_SIGNUP_VERIFY_LINK_FAIL")
            self.assertEqual(data["payload"]["message"], "user-out-of-sync")

    def test_verify_existing_email(self):
        response = self._verify_code(email="johnsmith@example.com")

        data = json.loads(response.data)
        self.assertEqual(data["type"], "GET_SIGNUP_VERIFY_LINK_FAIL")
        self.assertEqual(data["payload"]["status"], "already-verified")

    def test_verify_existing_email_mixed_case(self):
        response = self._verify_code(email="JohnSmith@example.com")

        data = json.loads(response.data)
        self.assertEqual(data["type"], "GET_SIGNUP_VERIFY_LINK_FAIL")
        self.assertEqual(data["payload"]["status"], "already-verified")

    def test_verify_code_after_captcha(self):
        res = self._verify_code_after_captcha()
        assert res.reached_state == SignupState.S7_VERIFY_LINK

    def test_verify_code_after_captcha_mixed_case(self):
        res = self._verify_code_after_captcha(
            email="MixedCase@Example.com",
            captcha_expected_message=SignupMsg.reg_new,
            verify_expect_success=True,
            verify_expected_message=None,
        )
        assert res.reached_state == SignupState.S7_VERIFY_LINK

    def test_verify_code_after_captcha_proofing_log_error(self):
        with patch("eduid.webapp.signup.views.verify_email_code") as mock_verify:
            mock_verify.side_effect = ProofingLogFailure("fail")
            res = self._verify_code_after_captcha(
                captcha_expected_message=SignupMsg.reg_new,
                verify_expect_success=False,
                verify_expected_message=CommonMsg.temp_problem,
            )
        assert res.reached_state == SignupState.S7_VERIFY_LINK

    def test_verify_code_after_captcha_wrong_csrf(self):
        data1 = {"csrf_token": "wrong-token"}
        res = self._verify_code_after_captcha(
            data1=data1,
            captcha_expect_success=False,
            captcha_expected_message=None,
        )
        assert res.response.json["payload"]["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_verify_code_after_captcha_dont_accept_tou(self):
        data1 = {"tou_accepted": False}
        res = self._verify_code_after_captcha(
            data1=data1, captcha_expect_success=False, captcha_expected_message=SignupMsg.no_tou
        )
        assert res.reached_state == SignupState.S5_CAPTCHA
