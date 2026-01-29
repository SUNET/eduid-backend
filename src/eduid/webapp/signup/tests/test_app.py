import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from http import HTTPStatus
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

from flask import url_for
from jwcrypto.jwk import JWK
from werkzeug.test import TestResponse

from eduid.common.clients.scim_client.testing import MockedScimAPIMixin
from eduid.common.config.base import EduidEnvironment
from eduid.common.misc.timeutil import utc_now
from eduid.common.testing_base import normalised_data
from eduid.userdb.credentials import Password
from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.signup import Invite, InviteMailAddress, InviteType
from eduid.userdb.signup.invite import InvitePhoneNumber, SCIMReference
from eduid.userdb.testing import SetupConfig
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
    S10_GET_STATE = "get_state"


@dataclass
class SignupResult:
    url: str
    reached_state: SignupState
    response: TestResponse


class SignupTests(EduidAPITestCase[SignupApp], MockedScimAPIMixin):
    def setUp(self, config: SetupConfig | None = None) -> None:
        if config is None:
            config = SetupConfig()
        config.copy_user_to_private = True
        super().setUp(config=config)

    def load_app(self, config: Mapping[str, Any]) -> SignupApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return signup_init_app(name="signup", test_config=config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
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
                "captcha_max_bad_attempts": 3,
                "environment": "dev",
                "scim_api_url": "http://localhost/scim/",
                "gnap_auth_data": {
                    "authn_server_url": "http://localhost/auth/",
                    "key_name": "app_name",
                    "client_jwk": JWK.generate(kid="testkey", kty="EC", size=256).export(as_dict=True),
                },
            }
        )
        return config

    def _get_captcha(
        self,
        expect_success: bool = True,
        expected_message: TranslatableMsg | None = None,
        logged_in: bool = False,
    ) -> SignupResult:
        eppn = None
        if logged_in:
            eppn = self.test_user.eppn

        with (
            self.session_cookie(self.browser, eppn=eppn, logged_in=logged_in) as client,
            self.app.test_request_context(),
            client.session_transaction() as sess,
        ):
            endpoint = url_for("signup.captcha_request")
            data = {
                "csrf_token": sess.get_csrf_token(),
            }
        response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

        if expect_success:
            type_ = "POST_SIGNUP_GET_CAPTCHA_SUCCESS"
            assert self.get_response_payload(response)["captcha_img"].startswith("data:image/png;base64,")
            assert self.get_response_payload(response)["captcha_audio"].startswith("data:audio/wav;base64,")
        else:
            type_ = "POST_SIGNUP_GET_CAPTCHA_FAIL"

        self._check_api_response(
            response,
            status=200,
            type_=type_,
            message=expected_message,
        )

        return SignupResult(url=endpoint, reached_state=SignupState.S9_GENERATE_CAPTCHA, response=response)

    def _get_state(self, logged_in: bool = False) -> SignupResult:
        eppn = None
        if logged_in:
            eppn = self.test_user.eppn

        with (
            self.session_cookie(self.browser, eppn=eppn, logged_in=logged_in) as client,
            self.app.test_request_context(),
        ):
            endpoint = url_for("signup.get_state")
            logger.info(f"Making GET request to {endpoint}")
            response = client.get(f"{endpoint}")

        self._check_api_response(
            response=response, status=200, type_="GET_SIGNUP_STATE_SUCCESS", assure_not_in_payload=["verification_code"]
        )
        return SignupResult(url=endpoint, reached_state=SignupState.S10_GET_STATE, response=response)

    # parameterized test methods
    def _captcha(
        self,
        captcha_data: Mapping[str, Any] | None = None,
        add_magic_cookie: bool = False,
        magic_cookie_name: str | None = None,
        expect_success: bool = True,
        expected_message: TranslatableMsg | None = None,
        expected_payload: Mapping[str, Any] | None = None,
        logged_in: bool = False,
    ) -> SignupResult:
        """
        :param captcha_data: to control the data POSTed to the /captcha endpoint
        :param add_magic_cookie: add magic cookie to the captcha request
        """

        eppn = None
        if logged_in:
            eppn = self.test_user.eppn

        with (
            self.session_cookie(self.browser, eppn=eppn, logged_in=logged_in) as client,
            self.app.test_request_context(),
            client.session_transaction() as sess,
        ):
            endpoint = url_for("signup.captcha_response")
            data = {
                "csrf_token": sess.get_csrf_token(),
                "internal_response": sess.signup.captcha.internal_answer,
            }

            if add_magic_cookie:
                assert self.app.conf.magic_cookie_name is not None
                assert self.app.conf.magic_cookie is not None
                if magic_cookie_name is None:
                    magic_cookie_name = self.app.conf.magic_cookie_name
                client.set_cookie(domain=self.test_domain, key=magic_cookie_name, value=self.app.conf.magic_cookie)
                # set backdoor captcha code
                data["internal_response"] = self.app.conf.captcha_backdoor_code

            if captcha_data is not None:
                data.update(captcha_data)
                # remove any None values
                data = {k: v for k, v in data.items() if v is not None}

            logger.info(f"Making request to {endpoint} with data:\n{data}")
            response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

            logger.info(f"Request to {endpoint} result: {response}")

            if response.status_code != HTTPStatus.OK:
                return SignupResult(url=endpoint, reached_state=SignupState.S3_COMPLETE_CAPTCHA, response=response)

            if expect_success:
                if not expected_payload:
                    assert self.get_response_payload(response)["state"]["captcha"]["completed"] is True

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
        data1: dict[str, Any] | None = None,
        given_name: str = "Test",
        surname: str = "Testdotter",
        email: str = "dummy@example.com",
        expect_success: bool = True,
        expected_message: TranslatableMsg | None = None,
        expected_payload: Mapping[str, Any] | None = None,
        logged_in: bool = False,
    ) -> SignupResult:
        """
        Trigger sending an email with a verification code.

        :param data1: to control the data POSTed to the verify email endpoint
        :param email: what email address to use
        """
        eppn = None
        if logged_in:
            eppn = self.test_user.eppn

        with self.session_cookie(self.browser, eppn=eppn, logged_in=logged_in) as client:
            with self.app.test_request_context():
                endpoint = url_for("signup.register_email")
                with client.session_transaction() as sess:
                    data = {
                        "given_name": given_name,
                        "surname": surname,
                        "email": email,
                        "csrf_token": sess.get_csrf_token(),
                    }
                if data1 is not None:
                    data.update(data1)

            logger.info(f"Making request to {endpoint} with data:\n{data}")
            response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

            logger.info(f"Request to {endpoint} result: {response}")

            if response.status_code != HTTPStatus.OK:
                return SignupResult(url=endpoint, reached_state=SignupState.S4_REGISTER_EMAIL, response=response)

            if expect_success:
                if not expected_payload:
                    assert self.get_response_payload(response)["state"]["already_signed_up"] is False
                    assert self.get_response_payload(response)["state"]["captcha"]["completed"] is True
                    assert self.get_response_payload(response)["state"]["email"]["address"] == email.lower()
                    assert self.get_response_payload(response)["state"]["email"]["completed"] is False
                    if "throttle_time_left" in self.get_response_payload(response)["state"]["email"]:
                        assert self.get_response_payload(response)["state"]["email"]["throttle_time_left"] > 0
                    assert self.get_response_payload(response)["state"]["email"]["expires_time_left"] > 0

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
        data1: dict[str, Any] | None = None,
        expect_success: bool = True,
        expected_message: TranslatableMsg | None = None,
        expected_payload: Mapping[str, Any] | None = None,
        logged_in: bool = False,
    ) -> SignupResult:
        """
        Verify registered email with a verification code.

        :param data1: to control the data POSTed to the verify email endpoint
        """
        eppn = None
        if logged_in:
            eppn = self.test_user.eppn

        with self.session_cookie(self.browser, eppn=eppn, logged_in=logged_in) as client:
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

            if response.status_code != HTTPStatus.OK:
                return SignupResult(url=endpoint, reached_state=SignupState.S5_VERIFY_EMAIL, response=response)

            if expect_success:
                if not expected_payload:
                    assert self.get_response_payload(response)["state"]["already_signed_up"] is False
                    assert self.get_response_payload(response)["state"]["captcha"]["completed"] is True
                    assert (
                        self.get_response_payload(response)["state"]["email"]["address"]
                        == self.get_response_payload(response)["state"]["email"]["address"].lower()
                    )
                    assert self.get_response_payload(response)["state"]["email"]["completed"] is True

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
        data1: dict[str, Any] | None = None,
        accept_tou: bool = True,
        tou_version: str | None = None,
        expect_success: bool = True,
        expected_message: TranslatableMsg | None = None,
        expected_payload: Mapping[str, Any] | None = None,
        logged_in: bool = False,
    ) -> SignupResult:
        """
        Verify registered email with a verification code.

        :param data1: to control the data POSTed to the verify email endpoint
        :param accept_tou: did the user accept the terms of use
        """
        if tou_version is None:
            tou_version = self.app.conf.tou_version

        eppn = None
        if logged_in:
            eppn = self.test_user.eppn

        with self.session_cookie(self.browser, eppn=eppn, logged_in=logged_in) as client:
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

            if response.status_code != HTTPStatus.OK:
                return SignupResult(url=endpoint, reached_state=SignupState.S2_ACCEPT_TOU, response=response)

            if expect_success:
                if not expected_payload:
                    assert self.get_response_payload(response)["state"]["tou"]["version"] == tou_version
                    assert self.get_response_payload(response)["state"]["tou"]["completed"] is True

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
        data1: dict[str, Any] | None = None,
        expect_success: bool = True,
        expected_message: TranslatableMsg | None = None,
        expected_payload: Mapping[str, Any] | None = None,
        logged_in: bool = False,
    ) -> SignupResult:
        """
        Generate a generated_password and return in state.

        :param data1: to control the data POSTed to the verify email endpoint
        """
        eppn = None
        if logged_in:
            eppn = self.test_user.eppn

        with self.session_cookie(self.browser, eppn=eppn, logged_in=logged_in) as client:
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

            if response.status_code != HTTPStatus.OK:
                return SignupResult(url=endpoint, reached_state=SignupState.S8_GENERATE_PASSWORD, response=response)

            if expect_success:
                if not expected_payload:
                    assert self.get_response_payload(response)["state"]["credentials"]["generated_password"] is not None

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
        given_name: str = "Test",
        surname: str = "Testdotter",
        email: str = "dummy@example.com",
        tou_accepted: bool = True,
        captcha_completed: bool = True,
        email_verified: bool = True,
        generated_password: str | None = "test_password",
        logged_in: bool = False,
    ) -> None:
        eppn = None
        if logged_in:
            eppn = self.test_user.eppn

        with (
            self.session_cookie(self.browser, eppn=eppn, logged_in=logged_in) as client,
            client.session_transaction() as sess,
        ):
            sess.signup.name.given_name = given_name
            sess.signup.name.surname = surname
            sess.signup.tou.completed = tou_accepted
            sess.signup.tou.version = "test_tou_v1"
            sess.signup.captcha.completed = captcha_completed
            sess.signup.email.address = email
            sess.signup.email.completed = email_verified
            sess.signup.email.reference = "test_ref"
            sess.signup.credentials.generated_password = generated_password

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.vccs.client.VCCSClient.add_credentials")
    def _create_user(
        self,
        mock_add_credentials: MagicMock,
        mock_request_user_sync: MagicMock,
        data: dict[str, Any] | None = None,
        custom_password: str | None = None,
        expect_success: bool = True,
        expected_message: TranslatableMsg | None = None,
        expected_payload: Mapping[str, Any] | None = None,
        logged_in: bool = False,
    ) -> SignupResult:
        """
        Create a new user with the data in the session.
        """
        mock_add_credentials.return_value = True
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = None
        if logged_in:
            eppn = self.test_user.eppn

        with self.session_cookie(self.browser, eppn=eppn, logged_in=logged_in) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    endpoint = url_for("signup.create_user")
                    _data = {
                        "csrf_token": sess.get_csrf_token(),
                        "use_suggested_password": True,
                        "use_webauthn": False,
                    }
                if custom_password is not None:
                    _data["custom_password"] = custom_password
                if data is not None:
                    _data.update(data)

            logger.info(f"Making request to {endpoint}")
            response = client.post(f"{endpoint}", json=_data)

            logger.info(f"Request to {endpoint} result: {response}")

            if response.status_code != HTTPStatus.OK:
                return SignupResult(url=endpoint, reached_state=SignupState.S6_CREATE_USER, response=response)

            if expect_success:
                if not expected_payload:
                    assert self.get_response_payload(response)["state"]["already_signed_up"] is True
                    assert self.get_response_payload(response)["state"]["tou"]["completed"] is True
                    assert self.get_response_payload(response)["state"]["captcha"]["completed"] is True
                    assert self.get_response_payload(response)["state"]["email"]["completed"] is True
                    assert self.get_response_payload(response)["state"]["credentials"]["completed"] is True
                    if custom_password:
                        assert self.get_response_payload(response)["state"]["credentials"]["custom_password"] is True
                        assert self.get_response_payload(response)["state"]["credentials"]["generated_password"] is None
                    else:
                        assert (
                            self.get_response_payload(response)["state"]["credentials"]["generated_password"]
                            == "test_password"
                        )
                    assert self.get_response_payload(response)["state"]["user_created"] is True
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
                if not logged_in:
                    with client.session_transaction() as sess:
                        eppn = sess.common.eppn
                        assert eppn is None

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
        phone_number = InvitePhoneNumber(number="tel:+46700000000", primary=True)
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
            expires_at=datetime(1970, 1, 1, 0, 0, 0, 0, UTC),
        )
        self.app.invite_db.save(invite=invite, is_in_database=False)
        return invite

    def _get_invite_data(
        self,
        email: str,
        invite_code: str,
        eppn: str | None = None,
        data1: dict[str, Any] | None = None,
        expect_success: bool = True,
        expected_message: TranslatableMsg | None = None,
        expected_payload: Mapping[str, Any] | None = None,
        logged_in: bool = False,
    ) -> SignupResult:
        """
        Get invite data from the invite data endpoint.
        """
        with self.app.test_request_context():
            endpoint = url_for("signup.get_invite")

        if eppn is None and logged_in:
            eppn = self.test_user.eppn

        with (
            self.session_cookie(self.browser, eppn=eppn, logged_in=logged_in) as client,
            client.session_transaction() as sess,
        ):
            data = {
                "invite_code": invite_code,
                "csrf_token": sess.get_csrf_token(),
            }
            if data1 is not None:
                data.update(data1)

        logger.info(f"Making request to {endpoint}")
        response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

        logger.info(f"Request to {endpoint} result: {response}")

        if response.status_code != HTTPStatus.OK:
            return SignupResult(url=endpoint, reached_state=SignupState.S0_GET_INVITE_DATA, response=response)

        if expect_success:
            if not expected_payload:
                assert self.get_response_payload(response)["email"] == email
                assert self.get_response_payload(response)["invite_type"] == InviteType.SCIM.value
                assert self.get_response_payload(response)["inviter_name"] == "Test Inviter"
                assert self.get_response_payload(response)["given_name"] == "Invite"
                assert self.get_response_payload(response)["surname"] == "Invitesson"
                assert self.get_response_payload(response)["inviter_name"] == "Test Inviter"
                assert self.get_response_payload(response)["expires_at"] == "1970-01-01T00:00:00+00:00"
                assert self.get_response_payload(response)["finish_url"] == "https://example.com/finish"
                assert self.get_response_payload(response)["preferred_language"] == "sv"
                if eppn is not None:
                    assert self.get_response_payload(response)["is_logged_in"] is True
                    assert self.get_response_payload(response)["user"]["given_name"] == "John"
                    assert self.get_response_payload(response)["user"]["surname"] == "Smith"
                    assert self.get_response_payload(response)["user"]["email"] == "johnsmith@example.com"

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
        data1: dict[str, Any] | None = None,
        expect_success: bool = True,
        expected_message: TranslatableMsg | None = None,
        expected_payload: Mapping[str, Any] | None = None,
        logged_in: bool = False,
    ) -> SignupResult:
        eppn = None
        if logged_in:
            eppn = self.test_user.eppn

        with self.session_cookie(self.browser, eppn=eppn, logged_in=logged_in) as client:
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
            assert response is not None, "response unexpected None"

            logger.info(f"Request to {endpoint} result: {response}")

            if response.status_code != HTTPStatus.OK:
                return SignupResult(url=endpoint, reached_state=SignupState.S1_ACCEPT_INVITE, response=response)

            assert response.json is not None, "response.json unexpected None"
            if expect_success:
                assert response.json.get("error", False) is False, (
                    f"expect_success {expect_success} but got error={response.json.get('error')}"
                )
                if not expected_payload:
                    payload = self.get_response_payload(response)
                    assert payload["state"]["tou"]["completed"] is False
                    assert payload["state"]["captcha"]["completed"] is False
                    assert payload["state"]["email"]["address"] == email
                    assert payload["state"]["email"]["completed"] is email_verified
                    assert payload["state"]["user_created"] is False
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
        mock_request_user_sync: MagicMock,
        eppn: str | None = None,
        data1: dict[str, Any] | None = None,
        expect_success: bool = True,
        expected_message: TranslatableMsg | None = None,
        expected_payload: Mapping[str, Any] | None = None,
    ) -> SignupResult:
        mock_request_user_sync.side_effect = self.request_user_sync
        logged_in = False
        if eppn:
            logged_in = True

        with self.session_cookie(self.browser, eppn=eppn, logged_in=logged_in) as client:
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

        if response.status_code != HTTPStatus.OK:
            return SignupResult(url=endpoint, reached_state=SignupState.S7_COMPLETE_INVITE, response=response)

        if expect_success:
            if not expected_payload:
                assert self.get_response_payload(response)["state"]["invite"]["initiated_signup"] is True
                assert self.get_response_payload(response)["state"]["invite"]["completed"] is True
                assert (
                    self.get_response_payload(response)["state"]["invite"]["finish_url"] == "https://example.com/finish"
                )

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

    def _get_code_backdoor(self, email: str, magic_cookie_name: str | None = None) -> TestResponse:
        """
        Test getting the generated verification code through the backdoor
        """
        with (
            self.session_cookie_and_magic_cookie_anon(self.browser, magic_cookie_name=magic_cookie_name) as client,
            client.session_transaction(),
            self.app.test_request_context(),
        ):
            return client.get(f"/get-code?email={email}")

    # actual tests
    def test_get_state_initial(self) -> None:
        res = self._get_state()
        assert res.reached_state == SignupState.S10_GET_STATE
        state = self.get_response_payload(res.response)["state"]
        assert state == {
            "already_signed_up": False,
            "captcha": {"completed": False},
            "credentials": {"completed": False, "custom_password": False, "generated_password": None},
            "email": {"address": None, "bad_attempts": 0, "bad_attempts_max": 3, "completed": False, "sent_at": None},
            "invite": {"completed": False, "finish_url": None, "initiated_signup": False},
            "name": {"given_name": None, "surname": None},
            "tou": {"completed": False, "version": "2016-v1"},
            "user_created": False,
        }, f"actual state is {state}"

    def test_get_state_initial_logged_in(self) -> None:
        res = self._get_state(logged_in=True)
        assert res.reached_state == SignupState.S10_GET_STATE
        state = self.get_response_payload(res.response)["state"]
        assert state == {
            "already_signed_up": True,
            "captcha": {"completed": False},
            "credentials": {"completed": False, "custom_password": False, "generated_password": None},
            "email": {"address": None, "bad_attempts": 0, "bad_attempts_max": 3, "completed": False, "sent_at": None},
            "invite": {"completed": False, "finish_url": None, "initiated_signup": False},
            "name": {"given_name": None, "surname": None},
            "tou": {"completed": False, "version": "2016-v1"},
            "user_created": False,
        }, f"actual state is {state}"

    def test_accept_tou(self) -> None:
        res = self._accept_tou()
        assert res.reached_state == SignupState.S2_ACCEPT_TOU

    def test_accept_tou_logged_in(self) -> None:
        self._accept_tou(logged_in=True, expect_success=False, expected_message=CommonMsg.logout_required)

    def test_not_accept_tou(self) -> None:
        res = self._accept_tou(accept_tou=False, expect_success=False, expected_message=SignupMsg.tou_not_completed)
        assert res.reached_state == SignupState.S2_ACCEPT_TOU

    def test_accept_tou_wrong_version(self) -> None:
        res = self._accept_tou(
            accept_tou=True,
            tou_version="bad_version",
            expect_success=False,
            expected_message=SignupMsg.tou_wrong_version,
        )
        assert res.reached_state == SignupState.S2_ACCEPT_TOU

    def test_accept_tou_bad_csrf(self) -> None:
        data1 = {"csrf_token": "bad-csrf-token"}
        res = self._accept_tou(data1=data1, expect_success=False, expected_message=None)
        assert res.reached_state == SignupState.S2_ACCEPT_TOU
        assert self.get_response_payload(res.response)["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_get_password(self) -> None:
        res = self._generate_password()
        assert res.reached_state == SignupState.S8_GENERATE_PASSWORD

    def test_get_password_bad_csrf(self) -> None:
        data1 = {"csrf_token": "bad-csrf-token"}
        res = self._generate_password(data1=data1, expect_success=False, expected_message=None)
        assert res.reached_state == SignupState.S8_GENERATE_PASSWORD
        assert self.get_response_payload(res.response)["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_captcha(self) -> None:
        res = self._get_captcha()
        assert res.reached_state == SignupState.S9_GENERATE_CAPTCHA
        res = self._captcha()
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_logged_in(self) -> None:
        res = self._get_captcha()
        assert res.reached_state == SignupState.S9_GENERATE_CAPTCHA
        self._captcha(logged_in=True, expect_success=False, expected_message=CommonMsg.logout_required)

    def test_captcha_new_wrong_csrf(self) -> None:
        data = {"csrf_token": "wrong-token"}
        res = self._captcha(captcha_data=data, expect_success=False, expected_message=None)
        assert self.get_response_payload(res.response)["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_captcha_fail(self) -> None:
        self._get_captcha()
        res = self._captcha(
            captcha_data={"internal_response": "wrong"},
            expect_success=False,
            expected_message=SignupMsg.captcha_failed,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_internal_fail_to_many_attempts(self) -> None:
        # run once to generate captcha
        self._get_captcha()
        self._captcha(
            captcha_data={"internal_response": "wrong"},
            expect_success=False,
            expected_message=SignupMsg.captcha_failed,
        )
        for _ in range(self.app.conf.captcha_max_bad_attempts):
            # make x bad attempts to get over the limit
            self._captcha(
                captcha_data={"internal_response": "wrong"},
                expect_success=False,
                expected_message=SignupMsg.captcha_failed,
            )
        # try one more time, should fail even as we use the correct code
        res = self._captcha(
            expect_success=False,
            expected_message=SignupMsg.captcha_failed,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_internal_not_requested(self) -> None:
        res = self._captcha(
            captcha_data={"internal_response": "not-requested"},
            expect_success=False,
            expected_message=SignupMsg.captcha_not_requested,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_backdoor(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        self._get_captcha()
        res = self._captcha(
            add_magic_cookie=True,
            expect_success=True,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_backdoor_right_code(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        self._get_captcha()
        res = self._captcha(
            add_magic_cookie=True,
            captcha_data={"internal_response": self.app.conf.captcha_backdoor_code},
            expect_success=True,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_backdoor_wrong_code(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        self._get_captcha()
        res = self._captcha(
            add_magic_cookie=True,
            captcha_data={"internal_response": "wrong"},
            expect_success=False,
            expected_message=SignupMsg.captcha_failed,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_no_backdoor_in_pro(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("production")
        self._get_captcha()
        res = self._captcha(
            add_magic_cookie=True,
            expect_success=False,
            expected_message=SignupMsg.captcha_failed,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_no_backdoor_misconfigured1(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = ""
        self.app.conf.environment = EduidEnvironment("dev")
        self._get_captcha()
        res = self._captcha(
            add_magic_cookie=True,
            expect_success=False,
            expected_message=SignupMsg.captcha_failed,
            magic_cookie_name="wrong_name",
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_no_backdoor_misconfigured2(self) -> None:
        self.app.conf.magic_cookie = ""
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")
        self._get_captcha()
        res = self._captcha(
            add_magic_cookie=True,
            expect_success=False,
            expected_message=SignupMsg.captcha_failed,
        )
        assert res.reached_state == SignupState.S3_COMPLETE_CAPTCHA

    def test_captcha_no_data_fail(self) -> None:
        with self.session_cookie(self.browser, eppn=None) as client:
            response = client.post("/captcha")
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertTrue(data["error"])
            self.assertEqual(data["type"], "POST_SIGNUP_CAPTCHA_FAIL")
            self.assertIn("csrf_token", data["payload"]["error"])

    def test_register_new_user(self) -> None:
        given_name = "John"
        surname = "Smith"
        email = "jsmith@example.com"
        self._get_captcha()
        self._captcha()
        res = self._register_email(
            given_name=given_name,
            surname=surname,
            email=email,
            expect_success=True,
            expected_message=None,
        )
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL
        assert self.app.messagedb.db_count() == 1
        with self.session_cookie(self.browser, eppn=None) as client, client.session_transaction() as sess:
            assert sess.signup.email.address == email
            assert sess.signup.name.given_name == given_name
            assert sess.signup.name.surname == surname

    def test_register_new_user_logged_in(self) -> None:
        given_name = "John"
        surname = "Smith"
        email = "jsmith@example.com"
        self._get_captcha()
        self._captcha()
        self._register_email(
            given_name=given_name,
            surname=surname,
            email=email,
            logged_in=True,
            expect_success=False,
            expected_message=CommonMsg.logout_required,
        )

    def test_register_new_user_mixed_case(self) -> None:
        self._get_captcha()
        self._captcha()
        mixed_case_email = "MixedCase@example.com"
        res = self._register_email(email=mixed_case_email)
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL

        with self.session_cookie_anon(self.browser) as client, client.session_transaction() as sess:
            assert sess.signup.email.address == mixed_case_email.lower()

    def test_register_existing_user(self) -> None:
        self._get_captcha()
        self._captcha()
        res = self._register_email(
            email="johnsmith@example.com", expect_success=False, expected_message=SignupMsg.email_used
        )
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL

    def test_register_existing_user_mixed_case(self) -> None:
        self._get_captcha()
        self._captcha()
        res = self._register_email(
            email="JohnSmith@Example.com", expect_success=False, expected_message=SignupMsg.email_used
        )
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL

    def test_register_existing_signup_user(self) -> None:
        # TODO: for backwards compatibility, remove when compatibility code in view is removed
        self._get_captcha()
        self._captcha()
        res = self._register_email(email="johnsmith2@example.com")
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL

    def test_register_existing_signup_user_mixed_case(self) -> None:
        # TODO: for backwards compatibility, remove when compatibility code in view is removed
        mixed_case_email = "JohnSmith2@Example.com"
        self._get_captcha()
        self._captcha()
        res = self._register_email(email=mixed_case_email)
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL

        with (
            self.session_cookie(self.browser, eppn=None, logged_in=False) as client,
            client.session_transaction() as sess,
        ):
            assert sess.signup.email.address == mixed_case_email.lower()

    def test_register_user_resend(self) -> None:
        self._get_captcha()
        self._captcha()
        self._register_email(expect_success=True, expected_message=None)
        with self.session_cookie_anon(self.browser) as client, client.session_transaction() as sess:
            sess.signup.email.sent_at = utc_now() - timedelta(minutes=6)
            verification_code = sess.signup.email.verification_code
        res = self._register_email(expect_success=True, expected_payload=None)
        with self.session_cookie_anon(self.browser) as client, client.session_transaction() as sess:
            assert verification_code == sess.signup.email.verification_code
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL
        assert self.app.messagedb.db_count() == 2

    def test_register_user_resend_email_throttled(self) -> None:
        self._get_captcha()
        self._captcha()
        self._register_email(expect_success=True, expected_message=None)
        res = self._register_email(expect_success=False, expected_message=SignupMsg.email_throttled)
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL
        assert self.app.messagedb.db_count() == 1

    def test_register_user_resend_mail_expired(self) -> None:
        self._get_captcha()
        self._captcha()
        self._register_email(expect_success=True, expected_message=None)
        with self.session_cookie_anon(self.browser) as client, client.session_transaction() as sess:
            sess.signup.email.sent_at = utc_now() - timedelta(hours=25)
            verification_code = sess.signup.email.verification_code
        res = self._register_email(expect_success=True, expected_payload=None)
        with self.session_cookie_anon(self.browser) as client, client.session_transaction() as sess:
            assert verification_code != sess.signup.email.verification_code
        assert res.reached_state == SignupState.S4_REGISTER_EMAIL
        assert self.app.messagedb.db_count() == 2

    def test_verify_email(self) -> None:
        self._get_captcha()
        self._captcha()
        self._register_email()
        response = self._verify_email()
        assert response.reached_state == SignupState.S5_VERIFY_EMAIL

    def test_verify_email_logged_in(self) -> None:
        self._get_captcha()
        self._captcha()
        self._register_email()
        self._verify_email(logged_in=True, expect_success=False, expected_message=CommonMsg.logout_required)

    def test_verify_email_wrong_code(self) -> None:
        self._get_captcha()
        self._captcha()
        self._register_email()
        data = {"verification_code": "wrong"}
        response = self._verify_email(
            data1=data, expect_success=False, expected_message=SignupMsg.email_verification_failed
        )
        assert response.reached_state == SignupState.S5_VERIFY_EMAIL

    def test_verify_email_wrong_code_to_many_attempts(self) -> None:
        self._get_captcha()
        self._captcha()
        self._register_email()
        data = {"verification_code": "wrong"}
        for _ in range(self.app.conf.email_verification_max_bad_attempts - 1):
            self._verify_email(data1=data, expect_success=False, expected_message=SignupMsg.email_verification_failed)
        response = self._verify_email(
            data1=data, expect_success=False, expected_message=SignupMsg.email_verification_too_many_tries
        )
        assert self.get_response_payload(response.response)["state"]["email"]["bad_attempts"] == 3
        assert self.get_response_payload(response.response)["state"]["captcha"]["completed"] is False
        assert response.reached_state == SignupState.S5_VERIFY_EMAIL

    def test_verify_email_mixed_case(self) -> None:
        mixed_case_email = "MixedCase@Example.com"
        self._get_captcha()
        self._captcha()
        self._register_email(email=mixed_case_email)
        response = self._verify_email()
        assert response.reached_state == SignupState.S5_VERIFY_EMAIL

        with self.session_cookie_anon(self.browser) as client, client.session_transaction() as sess:
            assert sess.signup.email.address == mixed_case_email.lower()

    def test_create_user(self) -> None:
        given_name = "Testaren Test"
        surname = "Test"
        email = "test@example.com"
        self._prepare_for_create_user(given_name=given_name, surname=surname, email=email)
        response = self._create_user(expect_success=True)
        assert response.reached_state == SignupState.S6_CREATE_USER

        with self.session_cookie_anon(self.browser) as client, client.session_transaction() as sess:
            eppn = sess.common.eppn
            assert eppn is not None
            assert sess.signup.credentials.generated_password is None
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user.given_name == given_name
        assert user.surname == surname
        assert user.mail_addresses.to_list()[0].email == email
        passwords = user.credentials.filter(Password)
        assert len(passwords) == 1
        assert passwords[0].is_generated is True

    def test_create_user_logged_in(self) -> None:
        email = "test@example.com"
        self._prepare_for_create_user(email=email)
        self._create_user(logged_in=True, expect_success=False, expected_message=CommonMsg.logout_required)

    def test_create_user_with_custom_password(self) -> None:
        given_name = "Testaren Test"
        surname = "Test"
        email = "test@example.com"
        self._prepare_for_create_user(given_name=given_name, surname=surname, email=email)
        data = {
            "use_suggested_password": False,
            "use_webauthn": False,
        }
        response = self._create_user(data=data, custom_password="9MbKxTHhCDK3Y9hhn6", expect_success=True)
        assert response.reached_state == SignupState.S6_CREATE_USER

        with self.session_cookie_anon(self.browser) as client, client.session_transaction() as sess:
            eppn = sess.common.eppn
            assert eppn is not None

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        passwords = user.credentials.filter(Password)
        assert len(passwords) == 1
        assert passwords[0].is_generated is False

    def test_create_user_with_weak_custom_password(self) -> None:
        given_name = "Testaren Test"
        surname = "Test"
        email = "test@example.com"
        self._prepare_for_create_user(given_name=given_name, surname=surname, email=email)
        data = {
            "use_suggested_password": True,
            "use_webauthn": False,
        }
        response = self._create_user(
            data=data, custom_password="abc123", expect_success=False, expected_message=SignupMsg.weak_custom_password
        )
        assert response.reached_state == SignupState.S6_CREATE_USER

    def test_create_user_out_of_sync(self) -> None:
        self._prepare_for_create_user()
        with patch("eduid.webapp.signup.helpers.save_and_sync_user") as mock_save:
            mock_save.side_effect = UserOutOfSync("unsync")
            response = self._create_user(expect_success=False, expected_message=CommonMsg.out_of_sync)
            assert response.reached_state == SignupState.S6_CREATE_USER

    def test_create_user_existing_email(self) -> None:
        self._prepare_for_create_user(email="johnsmith@example.com")
        response = self._create_user(expect_success=False, expected_message=SignupMsg.email_used)
        assert response.reached_state == SignupState.S6_CREATE_USER

    def test_create_user_proofing_log_error(self) -> None:
        self._prepare_for_create_user()
        with patch("eduid.webapp.signup.helpers.record_email_address") as mock_verify:
            mock_verify.side_effect = ProofingLogFailure("fail")
            res = self._create_user(
                expect_success=False,
                expected_message=CommonMsg.temp_problem,
            )
        assert res.reached_state == SignupState.S6_CREATE_USER

    def test_create_user_no_csrf(self) -> None:
        self._prepare_for_create_user()
        data = {"csrf_token": "wrong"}
        res = self._create_user(
            data=data,
            expect_success=False,
            expected_message=None,
        )
        assert self.get_response_payload(res.response)["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_create_user_no_captcha(self) -> None:
        self._prepare_for_create_user(captcha_completed=False)
        res = self._create_user(
            expect_success=False,
            expected_message=SignupMsg.captcha_not_completed,
        )
        assert res.reached_state == SignupState.S6_CREATE_USER

    def test_create_user_dont_accept_tou(self) -> None:
        self._prepare_for_create_user(tou_accepted=False)
        res = self._create_user(
            expect_success=False,
            expected_message=SignupMsg.tou_not_completed,
        )
        assert res.reached_state == SignupState.S6_CREATE_USER

    def test_create_user_no_password(self) -> None:
        self._prepare_for_create_user(generated_password=None)
        res = self._create_user(
            expect_success=False,
            expected_message=SignupMsg.password_not_generated,
        )
        assert res.reached_state == SignupState.S6_CREATE_USER

    def test_get_invite_data(self) -> None:
        invite = self._create_invite()
        primary_mail = invite.get_primary_mail_address()
        assert primary_mail
        res = self._get_invite_data(email=primary_mail, invite_code=invite.invite_code)
        assert res.reached_state == SignupState.S0_GET_INVITE_DATA

    def test_get_invite_data_already_logged_in(self) -> None:
        invite = self._create_invite()
        primary_mail = invite.get_primary_mail_address()
        assert primary_mail
        res = self._get_invite_data(
            email=primary_mail,
            invite_code=invite.invite_code,
            eppn=self.test_user.eppn,
            logged_in=True,
        )
        assert res.reached_state == SignupState.S0_GET_INVITE_DATA

    def test_accept_invite_via_email(self) -> None:
        invite = self._create_invite()
        primary_mail = invite.get_primary_mail_address()
        assert primary_mail
        res = self._accept_invite(email=primary_mail, invite_code=invite.invite_code)
        assert res.reached_state == SignupState.S1_ACCEPT_INVITE

    def test_accept_invite_via_other(self) -> None:
        invite = self._create_invite(send_email=False)
        primary_mail = invite.get_primary_mail_address()
        assert primary_mail
        res = self._accept_invite(email=primary_mail, invite_code=invite.invite_code, email_verified=False)
        assert res.reached_state == SignupState.S1_ACCEPT_INVITE

    def test_accept_invite_no_csrf(self) -> None:
        invite = self._create_invite()
        data1 = {"csrf_token": "wrong"}
        primary_mail = invite.get_primary_mail_address()
        assert primary_mail
        res = self._accept_invite(
            email=primary_mail,
            invite_code=invite.invite_code,
            data1=data1,
            expect_success=False,
            expected_message=None,
        )
        assert self.get_response_payload(res.response)["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_get_state_after_accept_invite(self) -> None:
        invite = self._create_invite()
        primary_mail = invite.get_primary_mail_address()
        assert primary_mail
        self._accept_invite(email=primary_mail, invite_code=invite.invite_code)
        res = self._get_state()
        assert res.reached_state == SignupState.S10_GET_STATE
        state = self.get_response_payload(res.response)["state"]
        assert normalised_data(state, exclude_keys=["expires_time_left", "throttle_time_left", "sent_at"]) == {
            "already_signed_up": False,
            "captcha": {"completed": False},
            "credentials": {"completed": False, "custom_password": False, "generated_password": None},
            "email": {
                "address": "dummy@example.com",
                "bad_attempts": 0,
                "bad_attempts_max": 3,
                "completed": True,
                "expires_time_max": 600,
                "throttle_time_max": 300,
            },
            "invite": {"completed": False, "finish_url": None, "initiated_signup": True},
            "name": {"given_name": "Invite", "surname": "Invitesson"},
            "tou": {"completed": False, "version": "2016-v1"},
            "user_created": False,
        }, f"Actual state {normalised_data(state, exclude_keys=['expires_time_left', 'throttle_time_left', 'sent_at'])}"

    def test_complete_invite_new_user(self) -> None:
        self.start_mocked_scim_api()

        invite = self._create_invite()
        primary_mail = invite.get_primary_mail_address()
        assert primary_mail
        self._accept_invite(email=primary_mail, invite_code=invite.invite_code)
        res = self._get_state()
        state_payload = self.get_response_payload(res.response)
        self._prepare_for_create_user(
            email=primary_mail,
            given_name=state_payload["state"]["name"]["given_name"],
            surname=state_payload["state"]["name"]["surname"],
        )
        self._create_user(expect_success=True)
        res = self._complete_invite()
        assert res.reached_state == SignupState.S7_COMPLETE_INVITE

        with self.session_cookie_anon(self.browser) as client, client.session_transaction() as sess:
            eppn = sess.common.eppn
            assert eppn is not None

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user.given_name == invite.given_name
        assert user.surname == invite.surname
        assert user.mail_addresses.to_list()[0].email == invite.get_primary_mail_address()

    def test_complete_invite_existing_user(self) -> None:
        self.start_mocked_scim_api()

        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        previous_given_name = user.given_name
        previous_surname = user.surname
        assert user.mail_addresses.primary
        invite = self._create_invite(email=user.mail_addresses.primary.email)
        primary_mail = invite.get_primary_mail_address()
        assert primary_mail
        self._accept_invite(email=primary_mail, invite_code=invite.invite_code)
        res = self._complete_invite(eppn=user.eppn)
        assert res.reached_state == SignupState.S7_COMPLETE_INVITE

        with self.session_cookie(self.browser, eppn=user.eppn) as client, client.session_transaction() as sess:
            eppn = sess.common.eppn
            assert eppn is not None

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user.given_name == previous_given_name
        assert user.surname == previous_surname
        assert user.mail_addresses.to_list()[0].email == invite.get_primary_mail_address()

    def test_complete_invite_existing_user_try_new_signup(self) -> None:
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        assert user.mail_addresses.primary is not None
        invite = self._create_invite(email=user.mail_addresses.primary.email)
        primary_mail = invite.get_primary_mail_address()
        assert primary_mail
        self._accept_invite(email=primary_mail, invite_code=invite.invite_code)
        self._prepare_for_create_user(email=primary_mail)
        res = self._create_user(expect_success=False, expected_message=SignupMsg.email_used)
        assert res.reached_state == SignupState.S6_CREATE_USER

    def test_get_code_backdoor(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        email = "johnsmith4@example.com"
        self._captcha(add_magic_cookie=True)
        self._register_email(email=email)
        response = self._get_code_backdoor(email=email)

        with self.session_cookie(self.browser, eppn=None) as client, client.session_transaction() as sess:
            assert response.text == sess.signup.email.verification_code

    def test_get_code_no_backdoor_in_pro(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("production")

        email = "johnsmith4@example.com"
        resp = self._get_code_backdoor(email=email)

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured1(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = ""
        self.app.conf.environment = EduidEnvironment("dev")

        email = "johnsmith4@example.com"
        resp = self._get_code_backdoor(email=email, magic_cookie_name="wrong_name")

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured2(self) -> None:
        self.app.conf.magic_cookie = ""
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        email = "johnsmith4@example.com"
        resp = self._get_code_backdoor(email=email)

        self.assertEqual(resp.status_code, 400)
