# -*- coding: utf-8 -*-

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Union
from uuid import uuid4

from flask import Response as FlaskResponse
from flask import url_for
from mock import patch

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.signup import Invite, InviteMailAddress, InviteType, SignupUser
from eduid.userdb.signup.invite import InvitePhoneNumber, InviteReference, SCIMReference
from eduid.webapp.common.api.exceptions import ProofingLogFailure
from eduid.webapp.common.api.messages import CommonMsg, TranslatableMsg
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.signup.app import SignupApp, signup_init_app
from eduid.webapp.signup.helpers import SignupMsg

logger = logging.getLogger(__name__)


class SignupState(Enum):
    S0_GET_INVITE_DATA = "get_invite_data"
    S1_ACCEPT_INVITE = "accept_invite"
    S2_ACCEPT_TOU = "accept_tou"
    S3_COMPLETE_CAPTCHA = "complete_captcha"
    S4_REGISTER_EMAIL = "register_email"
    S5_VERIFY_EMAIL = "verify_email"
    S6_CREATE_USER = "create_user"
    S7_COMPLETE_INVITE = "complete_invite"
    S8_GENERATE_PASSWORD = "generate_password"
    S9_GENERATE_CAPTCHA = "generate_captcha"


class OldSignupState(Enum):
    S5_CAPTCHA = "captcha"
    S6_MAIL_SENT_NO_USER = "no_user_created"
    S7_VERIFY_LINK = "verify_link"


@dataclass
class SignupResult:
    url: str
    reached_state: Union[SignupState, OldSignupState]
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
                "signup_url": "https://localhost/",
                "dashboard_url": "https://localhost/",
                "development": "DEBUG",
                "application_root": "/",
                "log_level": "DEBUG",
                "password_length": 10,
                "vccs_url": "http://turq:13085/",
                "default_finish_url": "https://www.eduid.se/",
                "recaptcha_public_key": "XXXX",
                "recaptcha_private_key": "XXXX",
                "environment": "dev",
            }
        )
        return config

    def _get_captcha(self):
        with self.session_cookie_anon(self.browser) as client:
            with self.app.test_request_context():
                endpoint = url_for("signup.captcha_request")
                with client.session_transaction() as sess:
                    data = {
                        "csrf_token": sess.get_csrf_token(),
                    }
        response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_GET_CAPTCHA_SUCCESS",
        )
        assert response.json["payload"]["captcha_img"].startswith("data:image/png;base64,")
        return SignupResult(url=endpoint, reached_state=SignupState.S9_GENERATE_CAPTCHA, response=response)

    # parameterized test methods
    @patch("eduid.webapp.signup.views.verify_recaptcha")
    def _captcha(
        self,
        mock_recaptcha: Any,
        captcha_data: Optional[Mapping[str, Any]] = None,
        recaptcha_return_value: bool = True,
        internal_captcha: bool = False,
        add_magic_cookie: bool = False,
        expect_success: bool = True,
        expected_message: Optional[TranslatableMsg] = None,
        expected_payload: Optional[Mapping[str, Any]] = None,
    ):
        """
        :param captcha_data: to control the data POSTed to the /captcha endpoint
        :param recaptcha_return_value: to mock recaptcha verification failure
        :param add_magic_cookie: add magic cookie to the captcha request
        """
        mock_recaptcha.return_value = recaptcha_return_value

        with self.session_cookie_anon(self.browser) as client:
            with self.app.test_request_context():
                endpoint = url_for("signup.captcha_response")
                if not internal_captcha:
                    with client.session_transaction() as sess:
                        data = {"csrf_token": sess.get_csrf_token(), "recaptcha_response": "dummy"}
                else:
                    self._get_captcha()
                    with client.session_transaction() as sess:
                        data = {
                            "csrf_token": sess.get_csrf_token(),
                            "internal_response": sess.signup.captcha.internal_answer,
                        }
                if captcha_data is not None:
                    data.update(captcha_data)
                    # remove any None values
                    data = {k: v for k, v in data.items() if v is not None}

                if add_magic_cookie:
                    client.set_cookie(
                        "localhost", key=self.app.conf.magic_cookie_name, value=self.app.conf.magic_cookie
                    )

                logger.info(f"Making request to {endpoint} with data:\n{data}")
                response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

                logger.info(f"Request to {endpoint} result: {response}")

                if response.status_code != 200:
                    return SignupResult(url=endpoint, reached_state=SignupState.S3_COMPLETE_CAPTCHA, response=response)

                if expect_success:
                    if not expected_payload:
                        assert response.json["payload"]["state"]["captcha"]["completed"] is True

                    self._check_api_response(
                        response,
                        status=200,
                        message=expected_message,
                        type_="POST_SIGNUP_CAPTCHA_SUCCESS",
                        payload=expected_payload,
                        assure_not_in_payload=["verification_code"],
                    )
                else:
                    self._check_api_response(
                        response,
                        status=200,
                        message=expected_message,
                        type_="POST_SIGNUP_CAPTCHA_FAIL",
                        payload=expected_payload,
                        assure_not_in_payload=["verification_code"],
                    )

                logger.info(f"Validated {endpoint} response:\n{response.json}")

                return SignupResult(url=endpoint, reached_state=SignupState.S3_COMPLETE_CAPTCHA, response=response)

    def _register_email(
        self,
        data1: Optional[dict] = None,
        email: str = "dummy@example.com",
        expect_success: bool = True,
        expected_message: Optional[TranslatableMsg] = None,
        expected_payload: Optional[Mapping[str, Any]] = None,
    ):
        """
        Trigger sending an email with a verification code.

        :param data1: to control the data POSTed to the verify email endpoint
        :param email: what email address to use
        """

        with self.session_cookie_anon(self.browser) as client:
            with self.app.test_request_context():
                endpoint = url_for("signup.register_email")
                with client.session_transaction() as sess:
                    data = {"email": email, "csrf_token": sess.get_csrf_token()}
                if data1 is not None:
                    data.update(data1)

            logger.info(f"Making request to {endpoint} with data:\n{data}")
            response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

            logger.info(f"Request to {endpoint} result: {response}")

            if response.status_code != 200:
                return SignupResult(url=endpoint, reached_state=SignupState.S4_REGISTER_EMAIL, response=response)

            if expect_success:
                if not expected_payload:
                    assert response.json["payload"]["state"]["captcha"]["completed"] is True
                    assert response.json["payload"]["state"]["email"]["address"] == email.lower()
                    assert response.json["payload"]["state"]["email"]["completed"] is False
                    if "throttle_time_left" in response.json["payload"]["state"]["email"]:
                        assert response.json["payload"]["state"]["email"]["throttle_time_left"] > 0
                    assert response.json["payload"]["state"]["email"]["expires_time_left"] > 0

                self._check_api_response(
                    response,
                    status=200,
                    message=expected_message,
                    type_="POST_SIGNUP_REGISTER_EMAIL_SUCCESS",
                    payload=expected_payload,
                    assure_not_in_payload=["verification_code"],
                )
            else:
                self._check_api_response(
                    response,
                    status=200,
                    message=expected_message,
                    type_="POST_SIGNUP_REGISTER_EMAIL_FAIL",
                    payload=expected_payload,
                    assure_not_in_payload=["verification_code"],
                )

            logger.info(f"Validated {endpoint} response:\n{response.json}")

            return SignupResult(url=endpoint, reached_state=SignupState.S4_REGISTER_EMAIL, response=response)

    def _verify_email(
        self,
        data1: Optional[dict] = None,
        expect_success: bool = True,
        expected_message: Optional[TranslatableMsg] = None,
        expected_payload: Optional[Mapping[str, Any]] = None,
    ):
        """
        Verify registered email with a verification code.

        :param data1: to control the data POSTed to the verify email endpoint
        """

        with self.session_cookie_anon(self.browser) as client:
            with self.app.test_request_context():
                endpoint = url_for("signup.verify_email")
                with client.session_transaction() as sess:
                    data = {
                        "verification_code": sess.signup.email.verification_code,
                        "csrf_token": sess.get_csrf_token(),
                    }
                if data1 is not None:
                    data.update(data1)

            logger.info(f"Making request to {endpoint} with data:\n{data}")
            response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

            logger.info(f"Request to {endpoint} result: {response}")

            if response.status_code != 200:
                return SignupResult(url=endpoint, reached_state=SignupState.S5_VERIFY_EMAIL, response=response)

            if expect_success:
                if not expected_payload:
                    assert response.json["payload"]["state"]["captcha"]["completed"] is True
                    assert (
                        response.json["payload"]["state"]["email"]["address"]
                        == response.json["payload"]["state"]["email"]["address"].lower()
                    )
                    assert response.json["payload"]["state"]["email"]["completed"] is True

                self._check_api_response(
                    response,
                    status=200,
                    message=expected_message,
                    type_="POST_SIGNUP_VERIFY_EMAIL_SUCCESS",
                    payload=expected_payload,
                    assure_not_in_payload=["verification_code"],
                )
            else:
                self._check_api_response(
                    response,
                    status=200,
                    message=expected_message,
                    type_="POST_SIGNUP_VERIFY_EMAIL_FAIL",
                    payload=expected_payload,
                    assure_not_in_payload=["verification_code"],
                )

            logger.info(f"Validated {endpoint} response:\n{response.json}")

            return SignupResult(url=endpoint, reached_state=SignupState.S5_VERIFY_EMAIL, response=response)

    def _accept_tou(
        self,
        data1: Optional[dict] = None,
        accept_tou: bool = True,
        tou_version: Optional[str] = None,
        expect_success: bool = True,
        expected_message: Optional[TranslatableMsg] = None,
        expected_payload: Optional[Mapping[str, Any]] = None,
    ):
        """
        Verify registered email with a verification code.

        :param data1: to control the data POSTed to the verify email endpoint
        :param accept_tou: did the user accept the terms of use
        """
        if tou_version is None:
            tou_version = self.app.conf.tou_version

        with self.session_cookie_anon(self.browser) as client:
            with self.app.test_request_context():
                endpoint = url_for("signup.accept_tou")
                with client.session_transaction() as sess:
                    data = {
                        "tou_accepted": accept_tou,
                        "tou_version": tou_version,
                        "csrf_token": sess.get_csrf_token(),
                    }
                if data1 is not None:
                    data.update(data1)

            logger.info(f"Making request to {endpoint} with data:\n{data}")
            response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

            logger.info(f"Request to {endpoint} result: {response}")

            if response.status_code != 200:
                return SignupResult(url=endpoint, reached_state=SignupState.S2_ACCEPT_TOU, response=response)

            if expect_success:
                if not expected_payload:
                    assert response.json["payload"]["state"]["tou"]["version"] == tou_version
                    assert response.json["payload"]["state"]["tou"]["completed"] is True

                self._check_api_response(
                    response,
                    status=200,
                    message=expected_message,
                    type_="POST_SIGNUP_ACCEPT_TOU_SUCCESS",
                    payload=expected_payload,
                    assure_not_in_payload=["verification_code"],
                )
            else:
                self._check_api_response(
                    response,
                    status=200,
                    message=expected_message,
                    type_="POST_SIGNUP_ACCEPT_TOU_FAIL",
                    payload=expected_payload,
                    assure_not_in_payload=["verification_code"],
                )

            logger.info(f"Validated {endpoint} response:\n{response.json}")

            return SignupResult(url=endpoint, reached_state=SignupState.S2_ACCEPT_TOU, response=response)

    def _generate_password(
        self,
        data1: Optional[dict] = None,
        expect_success: bool = True,
        expected_message: Optional[TranslatableMsg] = None,
        expected_payload: Optional[Mapping[str, Any]] = None,
    ):
        """
        Generate a password and return in state.

        :param data1: to control the data POSTed to the verify email endpoint
        """
        with self.session_cookie_anon(self.browser) as client:
            with self.app.test_request_context():
                endpoint = url_for("signup.get_password")
                with client.session_transaction() as sess:
                    data = {
                        "csrf_token": sess.get_csrf_token(),
                    }
                if data1 is not None:
                    data.update(data1)

            logger.info(f"Making request to {endpoint} with data:\n{data}")
            response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

            logger.info(f"Request to {endpoint} result: {response}")

            if response.status_code != 200:
                return SignupResult(url=endpoint, reached_state=SignupState.S8_GENERATE_PASSWORD, response=response)

            if expect_success:
                if not expected_payload:
                    assert response.json["payload"]["state"]["credentials"]["password"] is not None

                self._check_api_response(
                    response,
                    status=200,
                    message=expected_message,
                    type_="POST_SIGNUP_GET_PASSWORD_SUCCESS",
                    payload=expected_payload,
                    assure_not_in_payload=["verification_code"],
                )
            else:
                self._check_api_response(
                    response,
                    status=200,
                    message=expected_message,
                    type_="POST_SIGNUP_GET_PASSWORD_FAIL",
                    payload=expected_payload,
                    assure_not_in_payload=["verification_code"],
                )

            logger.info(f"Validated {endpoint} response:\n{response.json}")

            return SignupResult(url=endpoint, reached_state=SignupState.S8_GENERATE_PASSWORD, response=response)

    def _prepare_for_create_user(
        self,
        email: str = "dummy@example.com",
        tou_accepted: bool = True,
        captcha_completed: bool = True,
        email_verified: bool = True,
        generated_password: Optional[str] = "test_password",
    ):
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                sess.signup.tou.completed = tou_accepted
                sess.signup.tou.version = "test_tou_v1"
                sess.signup.captcha.completed = captcha_completed
                sess.signup.email.address = email
                sess.signup.email.completed = email_verified
                sess.signup.email.reference = "test_ref"
                sess.signup.credentials.password = generated_password

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def _create_user(
        self,
        mock_add_credentials: Any,
        mock_request_user_sync: Any,
        data1: Optional[dict] = None,
        expect_success: bool = True,
        expected_message: Optional[TranslatableMsg] = None,
        expected_payload: Optional[Mapping[str, Any]] = None,
    ):
        """
        Create a new user with the data in the session.
        """
        mock_add_credentials.return_value = True
        mock_request_user_sync.side_effect = self.request_user_sync
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    endpoint = url_for("signup.create_user")
                    data = {
                        "csrf_token": sess.get_csrf_token(),
                        "use_password": True,
                        "use_webauthn": False,
                    }
                if data1 is not None:
                    data.update(data1)

            logger.info(f"Making request to {endpoint}")
            response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

            logger.info(f"Request to {endpoint} result: {response}")

            if response.status_code != 200:
                return SignupResult(url=endpoint, reached_state=SignupState.S6_CREATE_USER, response=response)

            if expect_success:
                if not expected_payload:
                    assert response.json["payload"]["state"]["tou"]["completed"] is True
                    assert response.json["payload"]["state"]["captcha"]["completed"] is True
                    assert response.json["payload"]["state"]["email"]["completed"] is True
                    assert response.json["payload"]["state"]["credentials"]["completed"] is True
                    assert response.json["payload"]["state"]["credentials"]["password"] is not None
                    assert response.json["payload"]["state"]["user_created"] is True
                    with client.session_transaction() as sess:
                        assert sess.common.eppn is not None

                self._check_api_response(
                    response,
                    status=200,
                    message=expected_message,
                    type_="POST_SIGNUP_CREATE_USER_SUCCESS",
                    payload=expected_payload,
                    assure_not_in_payload=["verification_code"],
                )
            else:
                self._check_api_response(
                    response,
                    status=200,
                    message=expected_message,
                    type_="POST_SIGNUP_CREATE_USER_FAIL",
                    payload=expected_payload,
                    assure_not_in_payload=["verification_code"],
                )

            logger.info(f"Validated {endpoint} response:\n{response.json}")

            return SignupResult(url=endpoint, reached_state=SignupState.S6_CREATE_USER, response=response)

    def _create_invite(
        self, email: str = "dummy@example.com", invite_code: str = "test_code", send_email: bool = True
    ) -> Invite:
        mail_address = InviteMailAddress(email=email, primary=True)
        phone_number = InvitePhoneNumber(number="+46700000000", primary=True)
        invite_ref = SCIMReference(data_owner="test_owner", scim_id=uuid4())
        invite = Invite(
            invite_type=InviteType.SCIM,
            invite_reference=invite_ref,
            inviter_name="Test Inviter",
            invite_code=invite_code,
            mail_addresses=[mail_address],
            phone_numbers=[phone_number],
            send_email=send_email,
            given_name="Invite",
            surname="Invitesson",
            nin="190102031234",
            finish_url="https://example.com/finish",
            expires_at=datetime(1970, 1, 1, 0, 0, 0, 0, timezone.utc),
        )
        self.app.invite_db.save(invite=invite)
        return invite

    def _get_invite_data(
        self,
        email: str,
        invite_code: str,
        eppn: Optional[str] = None,
        data1: Optional[dict] = None,
        expect_success: bool = True,
        expected_message: Optional[TranslatableMsg] = None,
        expected_payload: Optional[Mapping[str, Any]] = None,
    ):
        """
        Get invite data from the invite data endpoint.
        """
        with self.app.test_request_context():
            endpoint = url_for("signup.get_invite")

        if eppn is None:
            with self.session_cookie_anon(self.browser) as client:
                with client.session_transaction() as sess:
                    data = {
                        "invite_code": invite_code,
                        "csrf_token": sess.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)
        else:
            with self.session_cookie(self.browser, eppn=eppn) as client:
                with client.session_transaction() as sess:
                    data = {
                        "invite_code": invite_code,
                        "csrf_token": sess.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)

        logger.info(f"Making request to {endpoint}")
        response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

        logger.info(f"Request to {endpoint} result: {response}")

        if response.status_code != 200:
            return SignupResult(url=endpoint, reached_state=SignupState.S0_GET_INVITE_DATA, response=response)

        if expect_success:
            if not expected_payload:
                assert response.json["payload"]["email"] == email
                assert response.json["payload"]["invite_type"] == InviteType.SCIM.value
                assert response.json["payload"]["inviter_name"] == "Test Inviter"
                assert response.json["payload"]["given_name"] == "Invite"
                assert response.json["payload"]["surname"] == "Invitesson"
                assert response.json["payload"]["inviter_name"] == "Test Inviter"
                assert response.json["payload"]["expires_at"] == "1970-01-01T00:00:00+00:00"
                assert response.json["payload"]["finish_url"] == "https://example.com/finish"
                assert response.json["payload"]["preferred_language"] == "sv"
                if eppn is not None:
                    assert response.json["payload"]["is_logged_in"] is True
                    assert response.json["payload"]["user"]["given_name"] == "John"
                    assert response.json["payload"]["user"]["surname"] == "Smith"
                    assert response.json["payload"]["user"]["email"] == "johnsmith@example.com"

            self._check_api_response(
                response,
                status=200,
                message=expected_message,
                type_="POST_SIGNUP_INVITE_DATA_SUCCESS",
                payload=expected_payload,
                assure_not_in_payload=["verification_code"],
            )
        else:
            self._check_api_response(
                response,
                status=200,
                message=expected_message,
                type_="POST_SIGNUP_INVITE_DATA_FAIL",
                payload=expected_payload,
                assure_not_in_payload=["verification_code"],
            )

        logger.info(f"Validated {endpoint} response:\n{response.json}")

        return SignupResult(url=endpoint, reached_state=SignupState.S0_GET_INVITE_DATA, response=response)

    def _accept_invite(
        self,
        email: str,
        invite_code: str,
        email_verified: bool = True,
        data1: Optional[dict] = None,
        expect_success: bool = True,
        expected_message: Optional[TranslatableMsg] = None,
        expected_payload: Optional[Mapping[str, Any]] = None,
    ):
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    endpoint = url_for("signup.accept_invite")
                    data = {
                        "invite_code": invite_code,
                        "csrf_token": sess.get_csrf_token(),
                    }
                if data1 is not None:
                    data.update(data1)

            logger.info(f"Making request to {endpoint}")
            response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

            logger.info(f"Request to {endpoint} result: {response}")

            if response.status_code != 200:
                return SignupResult(url=endpoint, reached_state=SignupState.S1_ACCEPT_INVITE, response=response)

            if expect_success:
                if not expected_payload:
                    assert response.json["payload"]["state"]["tou"]["completed"] is False
                    assert response.json["payload"]["state"]["captcha"]["completed"] is False
                    assert response.json["payload"]["state"]["email"]["address"] == email
                    assert response.json["payload"]["state"]["email"]["completed"] is email_verified
                    assert response.json["payload"]["state"]["user_created"] is False
                    with client.session_transaction() as sess:
                        assert sess.signup.invite.invite_code == invite_code

                self._check_api_response(
                    response,
                    status=200,
                    message=expected_message,
                    type_="POST_SIGNUP_ACCEPT_INVITE_SUCCESS",
                    payload=expected_payload,
                    assure_not_in_payload=["verification_code"],
                )
            else:
                self._check_api_response(
                    response,
                    status=200,
                    message=expected_message,
                    type_="POST_SIGNUP_ACCEPT_INVITE_FAIL",
                    payload=expected_payload,
                    assure_not_in_payload=["verification_code"],
                )

            logger.info(f"Validated {endpoint} response:\n{response.json}")

            return SignupResult(url=endpoint, reached_state=SignupState.S1_ACCEPT_INVITE, response=response)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _complete_invite(
        self,
        mock_request_user_sync,
        eppn: Optional[str] = None,
        data1: Optional[dict] = None,
        expect_success: bool = True,
        expected_message: Optional[TranslatableMsg] = None,
        expected_payload: Optional[Mapping[str, Any]] = None,
    ):
        mock_request_user_sync.side_effect = self.request_user_sync

        if eppn is None:
            with self.session_cookie_anon(self.browser) as client:
                with client.session_transaction() as sess:
                    with self.app.test_request_context():
                        endpoint = url_for("signup.complete_invite")
                        data = {
                            "csrf_token": sess.get_csrf_token(),
                        }
                    if data1 is not None:
                        data.update(data1)

                logger.info(f"Making request to {endpoint}")
                response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)
        else:
            with self.session_cookie(self.browser, eppn=eppn) as client:
                with client.session_transaction() as sess:
                    with self.app.test_request_context():
                        endpoint = url_for("signup.complete_invite")
                        data = {
                            "csrf_token": sess.get_csrf_token(),
                        }
                    if data1 is not None:
                        data.update(data1)

                logger.info(f"Making request to {endpoint}")
                response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

        logger.info(f"Request to {endpoint} result: {response}")

        if response.status_code != 200:
            return SignupResult(url=endpoint, reached_state=SignupState.S7_COMPLETE_INVITE, response=response)

        if expect_success:
            if not expected_payload:
                assert response.json["payload"]["state"]["invite"]["initiated_signup"] is True
                assert response.json["payload"]["state"]["invite"]["completed"] is True
                assert response.json["payload"]["state"]["invite"]["finish_url"] == "https://example.com/finish"

            self._check_api_response(
                response,
                status=200,
                message=expected_message,
                type_="POST_SIGNUP_COMPLETE_INVITE_SUCCESS",
                payload=expected_payload,
                assure_not_in_payload=["verification_code"],
            )
        else:
            self._check_api_response(
                response,
                status=200,
                message=expected_message,
                type_="POST_SIGNUP_COMPLETE_INVITE_FAIL",
                payload=expected_payload,
                assure_not_in_payload=["verification_code"],
            )

        logger.info(f"Validated {endpoint} response:\n{response.json}")

        return SignupResult(url=endpoint, reached_state=SignupState.S7_COMPLETE_INVITE, response=response)

    def _get_code_backdoor(
        self,
        email: str,
    ):
        """
        Test getting the generated verification code through the backdoor
        """
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction():
                with self.app.test_request_context():
                    client.set_cookie(
                        "localhost", key=self.app.conf.magic_cookie_name, value=self.app.conf.magic_cookie
                    )
                    return client.get(f"/get-code?email={email}")

    # actual tests
    def test_accept_tou(self):
        res = self._accept_tou()
        assert res.reached_state == SignupState.S2_ACCEPT_TOU

    def test_not_accept_tou(self):
        res = self._accept_tou(accept_tou=False, expect_success=False, expected_message=SignupMsg.tou_not_completed)
        assert res.reached_state == SignupState.S2_ACCEPT_TOU

    def test_accept_tou_wrong_version(self):
        res = self._accept_tou(
            accept_tou=True,
            tou_version="bad_version",
            expect_success=False,
            expected_message=SignupMsg.tou_wrong_version,
        )
        assert res.reached_state == SignupState.S2_ACCEPT_TOU

    def test_accept_tou_bad_csrf(self):
        data1 = {"csrf_token": "bad-csrf-token"}
        res = self._accept_tou(data1=data1, expect_success=False, expected_message=None)
        assert res.reached_state == SignupState.S2_ACCEPT_TOU
        assert res.response.json["payload"]["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_get_password(self):
        res = self._generate_password()
        assert res.reached_state == SignupState.S8_GENERATE_PASSWORD

    def test_get_password_bad_csrf(self):
        data1 = {"csrf_token": "bad-csrf-token"}
        res = self._generate_password(data1=data1, expect_success=False, expected_message=None)
        assert res.reached_state == SignupState.S8_GENERATE_PASSWORD
        assert res.response.json["payload"]["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_captcha(self):
        res = self._captcha()
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_internal(self):
        res = self._captcha(internal_captcha=True)
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_recaptcha_new_no_key(self):
        self.app.conf.recaptcha_public_key = ""
        res = self._captcha(expect_success=False, expected_message=SignupMsg.captcha_failed)
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_new_wrong_csrf(self):
        data = {"csrf_token": "wrong-token"}
        res = self._captcha(captcha_data=data, expect_success=False, expected_message=None)
        assert res.response.json["payload"]["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_captcha_fail(self):
        res = self._captcha(
            recaptcha_return_value=False, expect_success=False, expected_message=SignupMsg.captcha_failed
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_internal_fail(self):
        res = self._captcha(
            internal_captcha=True,
            captcha_data={"internal_response": "wrong"},
            expect_success=False,
            expected_message=SignupMsg.captcha_failed,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_internal_not_requested(self):
        res = self._captcha(
            captcha_data={"internal_response": "not-requested", "recaptcha_response": None},
            expect_success=False,
            expected_message=SignupMsg.captcha_not_requested,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_backdoor(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = "dev"

        res = self._captcha(
            recaptcha_return_value=False,
            add_magic_cookie=True,
            expect_success=True,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_no_backdoor_in_pro(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = "production"
        res = self._captcha(
            recaptcha_return_value=False,
            add_magic_cookie=True,
            expect_success=False,
            expected_message=SignupMsg.captcha_failed,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_no_backdoor_misconfigured1(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = ""
        self.app.conf.environment = "dev"
        res = self._captcha(
            recaptcha_return_value=False,
            add_magic_cookie=True,
            expect_success=False,
            expected_message=SignupMsg.captcha_failed,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_no_backdoor_misconfigured2(self):
        self.app.conf.magic_cookie = ""
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = "dev"
        res = self._captcha(
            recaptcha_return_value=False,
            add_magic_cookie=True,
            expect_success=False,
            expected_message=SignupMsg.captcha_failed,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_no_data_fail(self):
        with self.session_cookie_anon(self.browser) as client:
            response = client.post("/captcha")
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertEqual(data["error"], True)
            self.assertEqual(data["type"], "POST_SIGNUP_CAPTCHA_FAIL")
            self.assertIn("csrf_token", data["payload"]["error"])

    def test_register_new_user(self):
        self._captcha()
        res = self._register_email(expect_success=True, expected_message=None)
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL
        assert self.app.messagedb.db_count() == 1

    def test_register_new_user_mixed_case(self):
        self._captcha()
        mixed_case_email = "MixedCase@example.com"
        res = self._register_email(email=mixed_case_email)
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL

        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                assert sess.signup.email.address == mixed_case_email.lower()

    def test_register_existing_user(self):
        self._captcha()
        res = self._register_email(
            email="johnsmith@example.com", expect_success=False, expected_message=SignupMsg.email_used
        )
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL

    def test_register_existing_user_mixed_case(self):
        self._captcha()
        res = self._register_email(
            email="JohnSmith@Example.com", expect_success=False, expected_message=SignupMsg.email_used
        )
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL

    def test_register_existing_signup_user(self):
        # TODO: for backwards compatibility, remove when compatibility code in view is removed
        self._captcha()
        res = self._register_email(email="johnsmith2@example.com")
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL

    def test_register_existing_signup_user_mixed_case(self):
        # TODO: for backwards compatibility, remove when compatibility code in view is removed
        mixed_case_email = "JohnSmith2@Example.com"
        self._captcha()
        res = self._register_email(email=mixed_case_email)
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL

        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                assert sess.signup.email.address == mixed_case_email.lower()

    def test_register_user_resend(self):
        self._captcha()
        self._register_email(expect_success=True, expected_message=None)
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                sess.signup.email.sent_at = utc_now() - timedelta(minutes=6)
                verification_code = sess.signup.email.verification_code
        res = self._register_email(expect_success=True, expected_payload=None)
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                assert verification_code == sess.signup.email.verification_code
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL
        assert self.app.messagedb.db_count() == 2

    def test_register_user_resend_email_throttled(self):
        self._captcha()
        self._register_email(expect_success=True, expected_message=None)
        res = self._register_email(expect_success=False, expected_message=SignupMsg.email_throttled)
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL
        assert self.app.messagedb.db_count() == 1

    def test_register_user_resend_mail_expired(self):
        self._captcha()
        self._register_email(expect_success=True, expected_message=None)
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                sess.signup.email.sent_at = utc_now() - timedelta(hours=25)
                verification_code = sess.signup.email.verification_code
        res = self._register_email(expect_success=True, expected_payload=None)
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                assert verification_code != sess.signup.email.verification_code
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL
        assert self.app.messagedb.db_count() == 2

    def test_verify_email(self):
        self._captcha()
        self._register_email()
        response = self._verify_email()
        assert response.reached_state == SignupState.S5_VERIFY_EMAIL

    def test_verify_email_wrong_code(self):
        self._captcha()
        self._register_email()
        data = {"verification_code": "wrong"}
        response = self._verify_email(
            data1=data, expect_success=False, expected_message=SignupMsg.email_verification_failed
        )
        assert response.reached_state == SignupState.S5_VERIFY_EMAIL

    def test_verify_email_wrong_code_to_many_attempts(self):
        self._captcha()
        self._register_email()
        data = {"verification_code": "wrong"}
        for _ in range(self.app.conf.email_verification_max_bad_attempts):
            self._verify_email(data1=data, expect_success=False, expected_message=SignupMsg.email_verification_failed)
        response = self._verify_email(
            data1=data, expect_success=False, expected_message=SignupMsg.email_verification_too_many_tries
        )
        assert response.reached_state == SignupState.S5_VERIFY_EMAIL

    def test_verify_email_mixed_case(self):
        mixed_case_email = "MixedCase@Example.com"
        self._captcha()
        self._register_email(email=mixed_case_email)
        response = self._verify_email()
        assert response.reached_state == SignupState.S5_VERIFY_EMAIL

        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                assert sess.signup.email.address == mixed_case_email.lower()

    def test_create_user(self):
        email = "test@example.com"
        self._prepare_for_create_user(email=email)
        response = self._create_user(expect_success=True)
        assert response.reached_state == SignupState.S6_CREATE_USER

        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                eppn = sess.common.eppn
                assert eppn is not None
                assert sess.signup.credentials.password is None
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user is not None
        assert user.mail_addresses.to_list()[0].email == email

    def test_create_user_out_of_sync(self):
        self._prepare_for_create_user()
        with patch("eduid.webapp.signup.helpers.save_and_sync_user") as mock_save:
            mock_save.side_effect = UserOutOfSync("unsync")
            response = self._create_user(expect_success=False, expected_message=CommonMsg.out_of_sync)
            assert response.reached_state == SignupState.S6_CREATE_USER

    def test_create_user_existing_email(self):
        self._prepare_for_create_user(email="johnsmith@example.com")
        response = self._create_user(expect_success=False, expected_message=SignupMsg.email_used)
        assert response.reached_state == SignupState.S6_CREATE_USER

    def test_create_user_proofing_log_error(self):
        self._prepare_for_create_user()
        with patch("eduid.webapp.signup.helpers.record_email_address") as mock_verify:
            mock_verify.side_effect = ProofingLogFailure("fail")
            res = self._create_user(
                expect_success=False,
                expected_message=CommonMsg.temp_problem,
            )
        assert res.reached_state == SignupState.S6_CREATE_USER

    def test_create_user_no_csrf(self):
        self._prepare_for_create_user()
        data1 = {"csrf_token": "wrong"}
        res = self._create_user(
            data1=data1,
            expect_success=False,
            expected_message=None,
        )
        assert res.response.json["payload"]["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_create_user_no_captcha(self):
        self._prepare_for_create_user(captcha_completed=False)
        res = self._create_user(
            expect_success=False,
            expected_message=SignupMsg.captcha_not_completed,
        )
        assert res.reached_state == SignupState.S6_CREATE_USER

    def test_create_user_dont_accept_tou(self):
        self._prepare_for_create_user(tou_accepted=False)
        res = self._create_user(
            expect_success=False,
            expected_message=SignupMsg.tou_not_completed,
        )
        assert res.reached_state == SignupState.S6_CREATE_USER

    def test_create_user_no_password(self):
        self._prepare_for_create_user(generated_password=None)
        res = self._create_user(
            expect_success=False,
            expected_message=SignupMsg.password_not_generated,
        )
        assert res.reached_state == SignupState.S6_CREATE_USER

    def test_get_invite_data(self):
        invite = self._create_invite()
        res = self._get_invite_data(email=invite.get_primary_mail_address(), invite_code=invite.invite_code)
        assert res.reached_state == SignupState.S0_GET_INVITE_DATA

    def test_get_invite_data_already_logged_in(self):
        invite = self._create_invite()
        res = self._get_invite_data(
            email=invite.get_primary_mail_address(), invite_code=invite.invite_code, eppn=self.test_user.eppn
        )
        assert res.reached_state == SignupState.S0_GET_INVITE_DATA

    def test_accept_invite_via_email(self):
        invite = self._create_invite()
        res = self._accept_invite(email=invite.get_primary_mail_address(), invite_code=invite.invite_code)
        assert res.reached_state == SignupState.S1_ACCEPT_INVITE

    def test_accept_invite_via_other(self):
        invite = self._create_invite(send_email=False)
        res = self._accept_invite(
            email=invite.get_primary_mail_address(), invite_code=invite.invite_code, email_verified=False
        )
        assert res.reached_state == SignupState.S1_ACCEPT_INVITE

    def test_accept_invite_no_csrf(self):
        invite = self._create_invite()
        data1 = {"csrf_token": "wrong"}
        res = self._accept_invite(
            email=invite.get_primary_mail_address(),
            invite_code=invite.invite_code,
            data1=data1,
            expect_success=False,
            expected_message=None,
        )
        assert res.response.json["payload"]["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_complete_invite_new_user(self):
        invite = self._create_invite()
        self._accept_invite(email=invite.get_primary_mail_address(), invite_code=invite.invite_code)
        self._prepare_for_create_user(email=invite.get_primary_mail_address())
        self._create_user(expect_success=True)
        res = self._complete_invite()
        assert res.reached_state == SignupState.S7_COMPLETE_INVITE

        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                eppn = sess.common.eppn
                assert eppn is not None

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user is not None
        assert user.given_name == invite.given_name
        assert user.surname == invite.surname
        assert user.mail_addresses.to_list()[0].email == invite.get_primary_mail_address()

    def test_complete_invite_existing_user(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        previous_given_name = user.given_name
        previous_surname = user.surname
        invite = self._create_invite(email=user.mail_addresses.primary.email)
        self._accept_invite(email=invite.get_primary_mail_address(), invite_code=invite.invite_code)
        res = self._complete_invite(eppn=user.eppn)
        assert res.reached_state == SignupState.S7_COMPLETE_INVITE

        with self.session_cookie(self.browser, eppn=user.eppn) as client:
            with client.session_transaction() as sess:
                eppn = sess.common.eppn
                assert eppn is not None

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user is not None
        assert user.given_name == previous_given_name
        assert user.surname == previous_surname
        assert user.mail_addresses.to_list()[0].email == invite.get_primary_mail_address()

    def test_complete_invite_existing_user_try_new_signup(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        invite = self._create_invite(email=user.mail_addresses.primary.email)
        self._accept_invite(email=invite.get_primary_mail_address(), invite_code=invite.invite_code)
        self._prepare_for_create_user(email=invite.get_primary_mail_address())
        res = self._create_user(expect_success=False, expected_message=SignupMsg.email_used)
        assert res.reached_state == SignupState.S6_CREATE_USER

    def test_get_code_backdoor(self):
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = "dev"

        email = "johnsmith4@example.com"
        self._captcha(add_magic_cookie=True)
        self._register_email(email=email)
        response = self._get_code_backdoor(email=email)

        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                assert response.text == sess.signup.email.verification_code

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


# backwards compatibility


class OldSignupTests(SignupTests):

    # parameterized test methods

    @patch("eduid.webapp.signup.views.verify_recaptcha")
    def _captcha_new(
        self,
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
                    return SignupResult(url=_trycaptcha, reached_state=OldSignupState.S5_CAPTCHA, response=response)

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

                return SignupResult(url=_trycaptcha, reached_state=OldSignupState.S5_CAPTCHA, response=response)

    @patch("eduid.webapp.signup.views.verify_recaptcha")
    def _resend_email(self, mock_recaptcha: Any, data1: Optional[dict] = None, email: str = "dummy@example.com"):
        """
        Trigger re-sending an email with a verification code.
        :param data1: to control the data POSTed to the resend-verification endpoint
        :param email: what email address to use
        """
        mock_recaptcha.return_value = True

        with self.session_cookie_anon(self.browser) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"email": email, "csrf_token": sess.get_csrf_token()}
                if data1 is not None:
                    data.update(data1)

            return client.post("/resend-verification", data=json.dumps(data), content_type=self.content_type_json)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def _verify_code(
        self,
        mock_add_credentials: Any,
        mock_request_user_sync: Any,
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
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    # lower because we are purposefully calling it with a mixed case mail address in tests
                    sess.signup.email.address = email.lower()
                    sess.signup.email.verification_code = "dummy"
                    sess.signup.email.reference = "test reference"
                    sess.signup.email.sent_at = utc_now()
                    sess.signup.tou.completed = True
                    sess.signup.tou.version = "test_tou_v1"
                    sess.signup.captcha.completed = True
                    code = code or sess.signup.email.verification_code

            return client.get(f"/verify-link/{code}")

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

            with client.session_transaction() as sess:
                assert sess.signup.email.address == email.lower()
                verification_code = sess.signup.email.verification_code
                assert verification_code is not None

            _verify_link_url = f"/verify-link/{verification_code}"
            response2 = client.get(_verify_link_url)

            if verify_expect_success:
                if not verify_expected_payload:
                    verify_expected_payload = {
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

            return SignupResult(url=_verify_link_url, reached_state=OldSignupState.S7_VERIFY_LINK, response=response2)

    @patch("eduid.webapp.signup.views.verify_recaptcha")
    def _get_code_backdoor(
        self,
        mock_recaptcha: Any,
        email: str,
    ):
        """
        Test getting the generated verification code through the backdoor
        """
        mock_recaptcha.return_value = True
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction():
                with self.app.test_request_context():
                    self._captcha_new(email=email)

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

        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                assert sess.signup.email.address == email
                assert sess.signup.email.verification_code == resp.data.decode("ascii")

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
        assert res.reached_state == OldSignupState.S5_CAPTCHA

    def test_captcha_new_user_mixed_case(self):
        mixed_case_email = "MixedCase@example.com"
        res = self._captcha_new(email=mixed_case_email)
        assert res.reached_state == OldSignupState.S5_CAPTCHA

        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                assert sess.signup.email.address == mixed_case_email.lower()

    def test_captcha_new_no_key(self):
        self.app.conf.recaptcha_public_key = ""
        res = self._captcha_new(
            email="JohnSmith@Example.com", expect_success=False, expected_message=SignupMsg.no_recaptcha
        )
        assert res.reached_state == OldSignupState.S5_CAPTCHA

    def test_captcha_new_wrong_csrf(self):
        data = {"csrf_token": "wrong-token"}
        res = self._captcha_new(captcha_data=data, expect_success=False, expected_message=None)
        assert res.response.json["payload"]["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_captcha_existing_user(self):
        res = self._captcha_new(
            email="johnsmith@example.com", expect_success=False, expected_message=SignupMsg.old_email_used
        )
        assert res.reached_state == OldSignupState.S5_CAPTCHA

    def test_captcha_existing_user_mixed_case(self):
        res = self._captcha_new(
            email="JohnSmith@Example.com", expect_success=False, expected_message=SignupMsg.old_email_used
        )
        assert res.reached_state == OldSignupState.S5_CAPTCHA

    def test_captcha_remove_existing_signup_user(self):
        res = self._captcha_new(email="johnsmith2@example.com", expected_message=SignupMsg.reg_new)
        assert res.reached_state == OldSignupState.S5_CAPTCHA

    def test_captcha_remove_existing_signup_user_mixed_case(self):
        mixed_case_email = "JohnSmith2@Example.com"
        res = self._captcha_new(email=mixed_case_email, expected_message=SignupMsg.reg_new)
        assert res.reached_state == OldSignupState.S5_CAPTCHA

        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                assert sess.signup.email.address == mixed_case_email.lower()

    def test_captcha_fail(self):
        res = self._captcha_new(
            recaptcha_return_value=False, expect_success=False, expected_message=SignupMsg.no_recaptcha
        )
        assert res.reached_state == OldSignupState.S5_CAPTCHA

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
        assert res.reached_state == OldSignupState.S5_CAPTCHA

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
        assert res.reached_state == OldSignupState.S5_CAPTCHA

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
        assert res.reached_state == OldSignupState.S5_CAPTCHA

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
        assert res.reached_state == OldSignupState.S5_CAPTCHA

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
        assert res.reached_state == OldSignupState.S7_VERIFY_LINK

    def test_verify_code_after_captcha_mixed_case(self):
        res = self._verify_code_after_captcha(
            email="MixedCase@Example.com",
            captcha_expected_message=SignupMsg.reg_new,
            verify_expect_success=True,
            verify_expected_message=None,
        )
        assert res.reached_state == OldSignupState.S7_VERIFY_LINK

    def test_verify_code_after_captcha_proofing_log_error(self):
        with patch("eduid.webapp.signup.helpers.record_email_address") as mock_verify:
            mock_verify.side_effect = ProofingLogFailure("fail")
            res = self._verify_code_after_captcha(
                captcha_expected_message=SignupMsg.reg_new,
                verify_expect_success=False,
                verify_expected_message=CommonMsg.temp_problem,
            )
        assert res.reached_state == OldSignupState.S7_VERIFY_LINK

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
            data1=data1, captcha_expect_success=False, captcha_expected_message=SignupMsg.tou_not_accepted
        )
        assert res.reached_state == OldSignupState.S5_CAPTCHA
