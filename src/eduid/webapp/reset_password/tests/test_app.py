import copy
import datetime
import json
from collections.abc import Callable, Iterable, Mapping
from datetime import timedelta
from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote_plus

import pytest
from flask import url_for
from pydantic import ValidationError
from pytest_mock import MockerFixture
from werkzeug.test import TestResponse

from eduid.common.config.base import EduidEnvironment
from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials import Password, Webauthn
from eduid.userdb.fixtures.fido_credentials import webauthn_credential
from eduid.userdb.fixtures.fido_credentials import webauthn_credential as sample_credential
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.reset_password import ResetPasswordEmailAndPhoneState, ResetPasswordEmailState
from eduid.userdb.reset_password.element import CodeElement
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.api.testing import CSRFTestClient, EduidAPITestCase
from eduid.webapp.common.api.utils import get_zxcvbn_terms, hash_password
from eduid.webapp.common.authn.testing import MockVCCSClient
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

    @pytest.fixture(autouse=True)
    def setup(self, setup_api: None, mocker: MockerFixture) -> None:
        self.mocker = mocker
        self.other_test_user = UserFixtures().mocked_user_standard_2

    def load_app(self, config: Mapping[str, Any] | None) -> ResetPasswordApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_reset_password_app(test_config=config)

    @pytest.fixture(scope="class")
    def update_config(self) -> dict[str, Any]:
        config = self._get_base_config()
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
        captcha_completed: bool | None = True,
    ) -> TestResponse:
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

            if captcha_completed is not None:
                with c.session_transaction() as sess:
                    sess.reset_password.captcha.completed = captcha_completed

            response = c.post("/", data=json.dumps(data), content_type=self.content_type_json)
            assert response.status_code == 200
            return response

    def _get_status(self) -> TestResponse:
        with self.session_cookie_anon(self.browser) as c:
            return c.get("/", content_type=self.content_type_json)

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

    def _post_reset_password(
        self,
        data1: dict[str, Any] | None = None,
        data2: dict[str, Any] | None = None,
    ) -> TestResponse:
        """
        Test sending data from the reset password form, without extra security.
        First POST an email address to the / endpoint to create a reset password state,
        and then POST data to the endpoint to actually reset the password.

        :param data1: control the data sent to the / endpoint (an email address)
        :param data2: control the data sent to actually reset the password.
        """
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        self.mocker.patch("eduid.webapp.common.authn.vccs.get_vccs_client", return_value=MockVCCSClient())
        mock_request_user_sync.side_effect = self.request_user_sync

        # check that the user has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        assert len(verified_phone_numbers) == 1
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
                # This helper skips /verify-email/, so stand in for what that view does to the
                # session. Without it the view rejects the request as unverified, which is the
                # whole point of the guard - see test_post_verification_views_require_a_verified_session.
                sess.common.eppn = self.test_user.eppn

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

    def _post_choose_extra_sec(
        self,
        sendsms_side_effect: Callable[..., Any] | Exception | Iterable[Any] | None = None,
        data1: dict[str, Any] | None = None,
        data2: dict[str, Any] | None = None,
        data3: dict[str, Any] | None = None,
        repeat: bool = False,
    ) -> TestResponse:
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
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        self.mocker.patch("eduid.webapp.common.authn.vccs.get_vccs_client", return_value=MockVCCSClient())
        mock_sendsms = self.mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms", return_value=True)
        mock_request_user_sync.side_effect = self.request_user_sync
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
            assert response.status_code == 200

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

    def _post_reset_password_secure_phone(
        self,
        data1: dict[str, Any] | None = None,
        data2: dict[str, Any] | None = None,
    ) -> TestResponse:
        """
        Test fully resetting the password with extra security via a verification code sent by SMS.
        First initialize the reset password state by POSTing an email to the initial endpoint,
        then retrieve the state form the db and modify it in the way that choosing extra security
        with a verified phone number would, and finally POST the verification codes and
        the new password to finally reset the password.

        :param data1: To control the email sent to initiate the process
        :param data2: To control the data sent to actually finally reset the password.
        """
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        self.mocker.patch("eduid.webapp.common.authn.vccs.get_vccs_client", return_value=MockVCCSClient())
        self.mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms", return_value=True)
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self._post_email_address(data1=data1)
        state1 = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(state1, ResetPasswordEmailState)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        with self.app.test_request_context():
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
                # See _post_reset_password: this helper marks the state verified in the db
                # rather than going through /verify-email/, so the session needs the eppn too.
                sess.common.eppn = self.test_user.eppn
            data = {
                "csrf_token": self.get_response_payload(response)["csrf_token"],
                "email_code": state2.email_code.code,
                "phone_code": state2.phone_code.code,
                "password": new_password,
            }
            if data2 is not None:
                data.update(data2)

        return c.post(url, data=json.dumps(data), content_type=self.content_type_json)

    def _post_reset_password_security_key(
        self,
        data1: dict[str, Any] | None = None,
        credential_data: dict[str, Any] | None = None,
        data2: dict[str, Any] | None = None,
        fido2state: WebauthnState | None = None,
        custom_password: str | None = None,
    ) -> TestResponse:
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
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        self.mocker.patch("eduid.webapp.common.authn.vccs.get_vccs_client", return_value=MockVCCSClient())
        self.mocker.patch("fido2.cose.ES256.verify", return_value=True)
        mock_request_user_sync.side_effect = self.request_user_sync

        credential = sample_credential.to_dict()
        if credential_data:
            credential.update(credential_data)
        security_key = Webauthn.from_dict(credential)
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        user.credentials.add(security_key)
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
            url = url_for("reset_password.set_new_pw_extra_security_key", _external=True)

        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                sess.mfa_action.webauthn_state = fido2state
                new_password = generate_suggested_password(self.app.conf.password_length)
                sess.reset_password.generated_password_hash = hash_password(new_password)
                # See _post_reset_password: this helper marks the state verified in the db
                # rather than going through /verify-email/, so the session needs the eppn too.
                sess.common.eppn = self.test_user.eppn
            data = {
                "email_code": state.email_code.code,
                "password": custom_password or new_password,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
                "webauthn_response": SAMPLE_WEBAUTHN_REQUEST,
            }
            if data2 == {}:
                data = {}
            elif data2 is not None:
                data.update(data2)

        return c.post(url, data=json.dumps(data), content_type=self.content_type_json)

    def _post_reset_password_secure_external_mfa(
        self,
        data1: dict[str, Any] | None = None,
        data2: dict[str, Any] | None = None,
        external_mfa_state: dict[str, Any] | None = None,
        custom_password: str | None = None,
    ) -> TestResponse:
        """
        Test resetting the password with extra security via a external MFA.

        :param data1: to control what email is sent to create the state and start the process
        :param data2: to control the data POSTed to finally reset the password
        :param external_mfa_state: to control the external mfa state kept in the session
        """
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        self.mocker.patch("eduid.webapp.common.authn.vccs.get_vccs_client", return_value=MockVCCSClient())
        mock_request_user_sync.side_effect = self.request_user_sync

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
                # See _post_reset_password: this helper marks the state verified in the db
                # rather than going through /verify-email/, so the session needs the eppn too.
                sess.common.eppn = self.test_user.eppn
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

    def _get_email_code_backdoor(
        self, data1: dict[str, Any] | None = None, magic_cookie_name: str | None = None
    ) -> TestResponse:
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

    def _get_phone_code_backdoor(
        self,
        sendsms_side_effect: Callable[..., Any] | Exception | Iterable[Any] | None = None,
        magic_cookie_name: str | None = None,
    ) -> TestResponse:
        """
        Test choosing extra security via a confirmed phone number to reset the password,
        and getting the generated phone verification code through the backdoor
        """
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        self.mocker.patch("eduid.webapp.common.authn.vccs.get_vccs_client", return_value=MockVCCSClient())
        mock_sendsms = self.mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms", return_value=True)
        mock_request_user_sync.side_effect = self.request_user_sync
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
            assert response.status_code == 200

        with self.session_cookie_and_magic_cookie_anon(self.browser, magic_cookie_name=magic_cookie_name) as client:
            data = {
                "csrf_token": self.get_response_payload(response)["csrf_token"],
                "email_code": state.email_code.code,
                "phone_index": "0",
            }
            response = client.post(extra_security_phone_url, data=json.dumps(data), content_type=self.content_type_json)
            assert response.status_code == 200

            eppn = quote_plus(self.test_user.eppn)

            return client.get(f"/get-phone-code?eppn={eppn}")

    def _get_captcha(
        self,
        expect_success: bool = True,
        expected_message: TranslatableMsg | None = None,
    ) -> TestResponse:
        with self.session_cookie_anon(self.browser) as client:
            with self.app.test_request_context():
                endpoint = url_for("reset_password.captcha_request")
                with client.session_transaction() as sess:
                    data = {
                        "csrf_token": sess.get_csrf_token(),
                    }
        response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)

        if expect_success:
            type_ = "POST_RESET_PASSWORD_GET_CAPTCHA_SUCCESS"
            assert self.get_response_payload(response)["captcha_img"].startswith("data:image/png;base64,")
            assert self.get_response_payload(response)["captcha_audio"].startswith("data:audio/wav;base64,")
        else:
            type_ = "POST_RESET_PASSWORD_GET_CAPTCHA_FAIL"

        self._check_api_response(
            response,
            status=200,
            type_=type_,
            message=expected_message,
        )

        return response

    def _captcha(
        self,
        captcha_data: Mapping[str, Any] | None = None,
        add_magic_cookie: bool = False,
        magic_cookie_name: str | None = None,
        expect_success: bool = True,
        expected_message: TranslatableMsg | None = None,
        expected_payload: Mapping[str, Any] | None = None,
    ) -> TestResponse:
        """
        :param captcha_data: to control the data POSTed to the /captcha endpoint
        :param add_magic_cookie: add magic cookie to the captcha request
        """
        with self.session_cookie_anon(self.browser) as client:
            with self.app.test_request_context():
                endpoint = url_for("reset_password.captcha_response")
                with client.session_transaction() as sess:
                    data = {
                        "csrf_token": sess.get_csrf_token(),
                        "internal_response": sess.reset_password.captcha.internal_answer,
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

                response = client.post(f"{endpoint}", data=json.dumps(data), content_type=self.content_type_json)
                if response.status_code != HTTPStatus.OK:
                    return response

                if expect_success:
                    if not expected_payload:
                        assert self.get_response_payload(response)["captcha_completed"] is True

                    self._check_api_response(
                        response,
                        status=200,
                        message=expected_message,
                        type_="POST_RESET_PASSWORD_CAPTCHA_SUCCESS",
                        payload=expected_payload,
                        assure_not_in_payload=["verification_code"],
                    )
                else:
                    self._check_api_response(
                        response,
                        status=200,
                        message=expected_message,
                        type_="POST_RESET_PASSWORD_CAPTCHA_FAIL",
                        payload=expected_payload,
                        assure_not_in_payload=["verification_code"],
                    )

                return response

    # actual tests
    def test_correct_user_setup(self) -> None:
        # Check that user has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        assert len(verified_phone_numbers) == 1
        verified_identities = user.identities.verified
        assert len(verified_identities) == 3

    def test_get_zxcvbn_terms(self) -> None:
        with self.app.test_request_context():
            terms = get_zxcvbn_terms(self.test_user)
            assert terms == ["John", "Smith", "johnsmith", "johnsmith2"]

    def test_get_zxcvbn_terms_no_given_name(self) -> None:
        with self.app.test_request_context():
            self.test_user.given_name = ""
            self.app.central_userdb.save(self.test_user)
            terms = get_zxcvbn_terms(self.test_user)
            assert terms == ["Smith", "johnsmith", "johnsmith2"]

    def test_get_zxcvbn_terms_no_surname(self) -> None:
        with self.app.test_request_context():
            self.test_user.surname = ""
            self.app.central_userdb.save(self.test_user)
            terms = get_zxcvbn_terms(self.test_user)
            assert terms == ["John", "johnsmith", "johnsmith2"]

    def test_app_starts(self) -> None:
        assert self.app.conf.app_name == "reset_password"

    def test_captcha(self) -> None:
        self._get_captcha()
        self._captcha()

    def test_captcha_new_wrong_csrf(self) -> None:
        data = {"csrf_token": "wrong-token"}
        res = self._captcha(captcha_data=data, expect_success=False, expected_message=None)
        assert self.get_response_payload(res)["error"] == {"csrf_token": ["CSRF failed to validate"]}

    def test_captcha_fail(self) -> None:
        self._get_captcha()
        self._captcha(
            captcha_data={"internal_response": "wrong"},
            expect_success=False,
            expected_message=ResetPwMsg.captcha_failed,
        )

    def test_post_email_address(self) -> None:
        response = self._post_email_address()
        self._check_success_response(response, msg=ResetPwMsg.reset_pw_initialized, type_="POST_RESET_PASSWORD_SUCCESS")
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state
        assert state.email_address == "johnsmith@example.com"

    def test_post_email_address_throttled(self) -> None:
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

    def test_do_not_overwrite_email_state(self) -> None:
        # Avoid getting throttled
        self.app.conf.throttle_resend = datetime.timedelta()
        response1 = self._post_email_address()
        self._check_success_response(
            response1, msg=ResetPwMsg.reset_pw_initialized, type_="POST_RESET_PASSWORD_SUCCESS"
        )
        state1 = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state1
        assert state1.email_address == "johnsmith@example.com"
        assert state1.email_code.code is not None

        response2 = self._post_email_address()
        self._check_success_response(
            response2, msg=ResetPwMsg.reset_pw_initialized, type_="POST_RESET_PASSWORD_SUCCESS"
        )
        state2 = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state2
        assert state1.email_code.code == state2.email_code.code

    def test_overwrite_expired_email_state(self) -> None:
        response1 = self._post_email_address()
        self._check_success_response(
            response1, msg=ResetPwMsg.reset_pw_initialized, type_="POST_RESET_PASSWORD_SUCCESS"
        )
        state1 = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state1
        # Set created time 5 minutes before email_code_timeout
        state1.email_code.created_ts = utc_now() - (self.app.conf.email_code_timeout + datetime.timedelta(minutes=5))
        self.app.password_reset_state_db.save(state1)

        response2 = self._post_email_address()
        self._check_success_response(
            response2, msg=ResetPwMsg.reset_pw_initialized, type_="POST_RESET_PASSWORD_SUCCESS"
        )
        state2 = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state2
        assert state1.email_code.code != state2.email_code.code

    def test_resend_does_not_extend_expiry(self) -> None:
        self.app.conf.throttle_resend = timedelta(0)
        self._post_email_address()
        state1 = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state1 is not None
        first_created_ts = state1.email_code.created_ts

        self._post_email_address()
        state2 = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state2 is not None
        assert state2.email_code.code == state1.email_code.code
        assert state2.email_code.created_ts == first_created_ts

    def test_status_reports_expiry_from_first_issue(self) -> None:
        self.app.conf.throttle_resend = timedelta(0)
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None

        # Age the state to half its lifetime, without expiring it.
        half = self.app.conf.email_code_timeout / 2
        state.email_code.created_ts = utc_now() - half
        self.app.password_reset_state_db.save(state)

        # Resend. sent_at is re-stamped, but the expiry must not move.
        self._post_email_address()
        response = self._get_status()
        state_payload = self.get_response_payload(response)["state"]
        email_state = state_payload["email"]

        assert email_state["expires_time_max"] == self.app.conf.email_code_timeout.total_seconds()
        # Roughly half the window left, not the full window.
        assert 0 < email_state["expires_time_left"] <= half.total_seconds() + 60
        # The raw expiry is internal; only the derived countdown may reach the client.
        assert "email_code_expires_at" not in state_payload

    def test_status_sets_expiry_on_throttled_resend(self) -> None:
        """The throttled early-return path must set the expiry from first issue, not from now."""
        self.app.conf.throttle_resend = timedelta(minutes=5)
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None

        # Age the code to half its lifetime so "created_ts + timeout" and "utc_now() + timeout"
        # are an hour apart. Without this the rolling-window bug would be within rounding
        # distance of the correct value and the assertion below would not be able to see it.
        half = self.app.conf.email_code_timeout / 2
        state.email_code.created_ts = utc_now() - half
        self.app.password_reset_state_db.save(state)
        # Re-read, so the expected value carries the same precision the view will see.
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        expected = state.email_code.created_ts + self.app.conf.email_code_timeout

        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                sess.reset_password.email_code_expires_at = None

        response = self._post_email_address()
        self._check_success_response(response, msg=ResetPwMsg.email_send_throttled, type_="POST_RESET_PASSWORD_SUCCESS")
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                assert sess.reset_password.email_code_expires_at == expected

    def test_throttled_resend_populates_a_fresh_session(self) -> None:
        """Throttling is keyed on the state in the db, so a fresh browser can hit it.

        That exit returns before the normal session bookkeeping, so it has to do its own -
        otherwise GET / reports an expiry countdown for an address the session does not know.
        """
        assert self.test_user.mail_addresses.primary is not None
        self.app.conf.throttle_resend = timedelta(minutes=5)
        self._post_email_address()  # creates the state, and throttles the next send
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None

        # A browser that has never seen this reset before.
        browser = cast(CSRFTestClient, self.app.test_client())
        with self.session_cookie_anon(browser) as c:
            response = c.get("/", content_type=self.content_type_json)
            with c.session_transaction() as sess:
                sess.reset_password.captcha.completed = True
                assert sess.reset_password.email.address is None
            data = {
                "email": self.test_user.mail_addresses.primary.email,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
            }
            response = c.post("/", data=json.dumps(data), content_type=self.content_type_json)
            self._check_success_response(
                response, msg=ResetPwMsg.email_send_throttled, type_="POST_RESET_PASSWORD_SUCCESS"
            )
            with c.session_transaction() as sess:
                assert sess.reset_password.email.address == self.test_user.mail_addresses.primary.email
                assert sess.reset_password.email_code_expires_at == (
                    state.email_code.created_ts + self.app.conf.email_code_timeout
                )

    def test_post_unknown_email_address(self) -> None:
        data = {"email": "unknown@unplaced.un"}
        response = self._post_email_address(data1=data)
        self._check_error_response(response, msg=ResetPwMsg.user_not_found, type_="POST_RESET_PASSWORD_FAIL")

    def test_post_invalid_email_address(self) -> None:
        data = {"email": "invalid-address"}
        response = self._post_email_address(data1=data)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_FAIL",
            payload={"error": {"email": ["Not a valid email address."]}},
        )

    def test_post_reset_code(self) -> None:
        response = self._post_reset_code()
        assert response is not None
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_VERIFY_EMAIL_SUCCESS",
            payload={
                "email_address": "johnsmith@example.com",
                "extra_security": {
                    "swedish_eid": True,
                    "eidas": True,
                    "phone_numbers": [{"index": 0, "number": "XXXXXXXXXX09"}],
                },
                "success": True,
                "zxcvbn_terms": ["John", "Smith", "johnsmith", "johnsmith2"],
            },
        )

    def test_post_reset_code_unknown_email(self) -> None:
        data1 = {"email": "unknown@unknown.com"}
        assert not self._post_reset_code(data1=data1)

    def test_post_reset_code_no_extra_sec(self) -> None:
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

    def test_post_reset_code_extra_security_alternatives_security_key(self) -> None:
        # add security key to user
        self.add_security_key_to_user(
            eppn=self.test_user_eppn, keyhandle=webauthn_credential.keyhandle, mfa_approved=True
        )
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

    def test_post_reset_wrong_code(self) -> None:
        data2 = {"email_code": "wrong-code"}
        response = self._post_reset_code(data2=data2)
        assert response is not None
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.state_not_found
        )

    def _post_verify_email_no_session(self, email_code: str) -> TestResponse:
        """POST a code to /verify-email/ from a browser with no reset-password session state."""
        with self.app.test_request_context():
            verify_url = url_for("reset_password.verify_email", _external=True)
        # A brand new client, so no cookie from any previous request in this test.
        browser = cast(CSRFTestClient, self.app.test_client())
        with self.session_cookie_anon(browser) as c:
            with c.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = {"email_code": email_code, "csrf_token": csrf_token}
            return c.post(verify_url, data=json.dumps(data), content_type=self.content_type_json)

    def test_verify_email_without_session_is_rejected(self) -> None:
        """A valid code with no identity hint must not resolve anything."""
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None

        response = self._post_verify_email_no_session(email_code=state.email_code.code)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.email_address_required
        )

    @staticmethod
    def _response_without_csrf(response: TestResponse) -> dict[str, Any]:
        """The whole FSA response with the per-response CSRF nonce removed.

        A fresh csrf_token is minted for every response, so two responses issued to two
        different sessions can never be byte-identical. Everything an attacker could learn
        something from - type, error, and the rest of the payload - must be.
        """
        _json = copy.deepcopy(response.json)
        assert isinstance(_json, dict), "Response has invalid JSON"
        assert isinstance(_json.get("payload"), dict), "Response has no payload"
        # Guard the comparisons below against silently weakening if the field ever moves.
        assert "csrf_token" in _json["payload"], "Expected a csrf_token in the payload"
        del _json["payload"]["csrf_token"]
        return _json

    def _post_verify_email_cross_device(self, email_code: str, email: str | None) -> TestResponse:
        """POST a code from a fresh browser with no reset-password session state."""
        with self.app.test_request_context():
            verify_url = url_for("reset_password.verify_email", _external=True)
        browser = cast(CSRFTestClient, self.app.test_client())
        with self.session_cookie_anon(browser) as c:
            with c.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data: dict[str, Any] = {"email_code": email_code, "csrf_token": csrf_token}
            if email is not None:
                data["email"] = email
            return c.post(verify_url, data=json.dumps(data), content_type=self.content_type_json)

    def test_verify_email_no_hint_asks_for_email_address(self) -> None:
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None

        response = self._post_verify_email_cross_device(email_code=state.email_code.code, email=None)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.email_address_required
        )
        # Nothing resolved, so nothing was counted against the state.
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        assert state.bad_attempts == 0

    def test_verify_email_cross_device_with_email_succeeds(self) -> None:
        assert self.test_user.mail_addresses.primary is not None
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None

        response = self._post_verify_email_cross_device(
            email_code=state.email_code.code, email=self.test_user.mail_addresses.primary.email
        )
        assert response.status_code == 200
        assert self.get_response_payload(response)["email_address"] == "johnsmith@example.com"

    def test_unknown_email_no_pending_reset_and_wrong_code_are_indistinguishable(self) -> None:
        """No response may reveal whether the account, the reset request, or the code is right."""
        # The other test user is not loaded into the central userdb by the test setup, so
        # put it there - otherwise "known account without a reset" would not be known at all
        # and this test would pass without exercising the distinction it exists to rule out.
        self.amdb.save(self.other_test_user)
        assert self.other_test_user.mail_addresses.primary is not None
        assert self.app.central_userdb.get_user_by_mail(self.other_test_user.mail_addresses.primary.email) is not None
        assert self.test_user.mail_addresses.primary is not None
        self._post_email_address()  # a reset exists for test_user, not for anyone else

        # One code, used for all three arms, that cannot accidentally be the real one.
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        wrong_code = "wrong-code"
        assert wrong_code != state.email_code.code

        unknown = self._post_verify_email_cross_device(email_code=wrong_code, email="nobody@example.com")
        known_no_reset = self._post_verify_email_cross_device(
            email_code=wrong_code, email=self.other_test_user.mail_addresses.primary.email
        )
        # Known account, pending reset, wrong code - the third way of ending up nowhere.
        bad_code = self._post_verify_email_cross_device(
            email_code=wrong_code, email=self.test_user.mail_addresses.primary.email
        )

        for _response in (unknown, known_no_reset, bad_code):
            self._check_error_response(
                _response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.state_not_found
            )
        assert unknown.status_code == known_no_reset.status_code == bad_code.status_code
        assert self._response_without_csrf(unknown) == self._response_without_csrf(known_no_reset)
        assert self._response_without_csrf(unknown) == self._response_without_csrf(bad_code)

    def _retry_verify_email_same_browser(self, browser: CSRFTestClient, email_code: str, email: str) -> TestResponse:
        """POST a code again from a browser that has already been served a response.

        The csrf token is fetched through that same browser, so whatever session state the
        previous response left behind - a dropped cookie or a stale one - is the state in
        play. Using a fresh test_client() here instead would prove nothing about recovery.
        """
        with self.app.test_request_context():
            verify_url = url_for("reset_password.verify_email", _external=True)
        csrf_response = browser.get("/", content_type=self.content_type_json)
        data = {
            "email_code": email_code,
            "email": email,
            "csrf_token": self.get_response_payload(csrf_response)["csrf_token"],
        }
        return browser.post(verify_url, data=json.dumps(data), content_type=self.content_type_json)

    def test_other_user_session_recovers_when_email_posted(self) -> None:
        """A session for another user is cleared, so the retry succeeds."""
        assert self.test_user.mail_addresses.primary is not None
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None

        with self.app.test_request_context():
            verify_url = url_for("reset_password.verify_email", _external=True)

        browser = cast(CSRFTestClient, self.app.test_client())
        with self.session_cookie(browser, eppn=self.other_test_user.eppn) as c:
            with c.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = {
                "email_code": state.email_code.code,
                "email": self.test_user.mail_addresses.primary.email,
                "csrf_token": csrf_token,
            }
            response = c.post(verify_url, data=json.dumps(data), content_type=self.content_type_json)

        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.invalid_session
        )

        # The dead end is now recoverable: retry through the very browser that was just
        # rejected. It only resolves through the email fallback if the foreign session is
        # really gone; if the cookie survived, resolution would key on the stale eppn again.
        retry = self._retry_verify_email_same_browser(
            browser, email_code=state.email_code.code, email=self.test_user.mail_addresses.primary.email
        )
        assert retry.status_code == 200
        assert self.get_response_payload(retry)["email_address"] == "johnsmith@example.com"

    def test_stale_reset_session_for_other_address_recovers(self) -> None:
        """A reset session for another *address* is cleared too, not just one for another eppn.

        start_reset_pw leaves an address in the session without an eppn, so this is the same
        dead end as the test above, one identity hint down.
        """
        self.amdb.save(self.other_test_user)
        assert self.other_test_user.mail_addresses.primary is not None
        assert self.test_user.mail_addresses.primary is not None
        other_email = self.other_test_user.mail_addresses.primary.email

        # self.browser now holds a reset-password session for the test user's address, with
        # no eppn - exactly the state start_reset_pw leaves behind.
        self._post_email_address()
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                assert sess.common.eppn is None
                assert sess.reset_password.email.address == self.test_user.mail_addresses.primary.email

        # The code the user is about to submit belongs to a reset for the *other* address.
        other_state = ResetPasswordEmailState(
            eppn=self.other_test_user.eppn,
            email_address=other_email,
            email_code=CodeElement(code="654321", created_by="test", is_verified=False),
        )
        self.app.password_reset_state_db.save(other_state, is_in_database=False)

        with self.app.test_request_context():
            verify_url = url_for("reset_password.verify_email", _external=True)
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = {"email_code": "654321", "email": other_email, "csrf_token": csrf_token}
            response = c.post(verify_url, data=json.dumps(data), content_type=self.content_type_json)

        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.invalid_session
        )
        # The posted address was never resolved against anything, so the session user's own
        # state must be untouched - in particular it must not have taken a bad attempt.
        stale_state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert stale_state is not None
        assert stale_state.bad_attempts == 0

        # And the dead end is gone: the same browser can now complete the other reset.
        retry = self._retry_verify_email_same_browser(self.browser, email_code="654321", email=other_email)
        assert retry.status_code == 200
        assert self.get_response_payload(retry)["email_address"] == other_email

    def test_unknown_email_in_other_user_session_gives_same_response(self) -> None:
        """Unknown and known-but-not-mine must be indistinguishable - no enumeration oracle."""
        assert self.test_user.mail_addresses.primary is not None
        self._post_email_address()

        with self.app.test_request_context():
            verify_url = url_for("reset_password.verify_email", _external=True)

        def _post(email: str) -> TestResponse:
            browser = cast(CSRFTestClient, self.app.test_client())
            with self.session_cookie(browser, eppn=self.other_test_user.eppn) as c:
                with c.session_transaction() as sess:
                    csrf_token = sess.get_csrf_token()
                data = {"email_code": "123456", "email": email, "csrf_token": csrf_token}
                return c.post(verify_url, data=json.dumps(data), content_type=self.content_type_json)

        known = _post(self.test_user.mail_addresses.primary.email)
        unknown = _post("nobody@example.com")

        assert known.status_code == unknown.status_code
        assert self._response_without_csrf(known) == self._response_without_csrf(unknown)

    def test_verify_email_cross_device_binds_session_for_rest_of_flow(self) -> None:
        """After a successful fallback, the session carries the identity onward."""
        assert self.test_user.mail_addresses.primary is not None
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None

        with self.app.test_request_context():
            verify_url = url_for("reset_password.verify_email", _external=True)
        browser = cast(CSRFTestClient, self.app.test_client())
        with self.session_cookie_anon(browser) as c:
            with c.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = {
                "email_code": state.email_code.code,
                "email": self.test_user.mail_addresses.primary.email,
                "csrf_token": csrf_token,
            }
            response = c.post(verify_url, data=json.dumps(data), content_type=self.content_type_json)
            assert response.status_code == 200

            with c.session_transaction() as sess:
                assert sess.common.eppn == self.test_user.eppn
                assert sess.reset_password.email.address == self.test_user.mail_addresses.primary.email

    def test_wrong_code_does_not_downgrade_phone_state(self) -> None:
        """A wrong code must not reach the phone-expiry branch, which mutates the state."""
        self.mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms", return_value=True)
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(state, ResetPasswordEmailState)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        with self.app.test_request_context():
            state.extra_security = get_extra_security_alternatives(user)
            state.email_code.is_verified = True
            self.app.password_reset_state_db.save(state)
            send_verify_phone_code(state, state.extra_security["phone_numbers"][0]["number"])

        upgraded = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(upgraded, ResetPasswordEmailAndPhoneState)

        # Expire the phone code, then submit a WRONG email code.
        self.app.conf.phone_code_timeout = timedelta(0)
        with self.app.test_request_context():
            verify_url = url_for("reset_password.verify_email", _external=True)
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = {"email_code": "wrong-code", "csrf_token": csrf_token}
            response = c.post(verify_url, data=json.dumps(data), content_type=self.content_type_json)

        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.state_not_found
        )
        # The state must NOT have been downgraded back to a plain email state.
        after = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(after, ResetPasswordEmailAndPhoneState)

    def test_non_ascii_code_is_rejected_cleanly(self) -> None:
        """A non-ASCII code is just a wrong code, not an unhandled TypeError from compare_digest."""
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None

        with self.app.test_request_context():
            verify_url = url_for("reset_password.verify_email", _external=True)
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = {"email_code": "åäö123", "csrf_token": csrf_token}
            response = c.post(verify_url, data=json.dumps(data), content_type=self.content_type_json)

        assert response.status_code == 200
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.state_not_found
        )

    def test_correct_but_expired_code_still_reports_expired(self) -> None:
        """Comparing before checking expiry means legitimate users see the right message."""
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        self.app.conf.email_code_timeout = timedelta(0)

        with self.app.test_request_context():
            verify_url = url_for("reset_password.verify_email", _external=True)
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = {"email_code": state.email_code.code, "csrf_token": csrf_token}
            response = c.post(verify_url, data=json.dumps(data), content_type=self.content_type_json)

        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.expired_email_code
        )

    def _post_verify_email(self, email_code: str) -> TestResponse:
        """POST a code to /verify-email/ reusing the session established by _post_email_address."""
        with self.app.test_request_context():
            verify_url = url_for("reset_password.verify_email", _external=True)
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = {"email_code": email_code, "csrf_token": csrf_token}
            return c.post(verify_url, data=json.dumps(data), content_type=self.content_type_json)

    def test_wrong_code_increments_bad_attempts(self) -> None:
        self._post_email_address()

        response = self._post_verify_email(email_code="wrong-code")
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.state_not_found
        )

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        assert state.bad_attempts == 1

    def test_third_wrong_code_locks_state(self) -> None:
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        correct_code = state.email_code.code

        for _ in range(self.app.conf.email_code_max_bad_attempts):
            response = self._post_verify_email(email_code="wrong-code")
            self._check_error_response(
                response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.state_not_found
            )

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        assert state.bad_attempts == self.app.conf.email_code_max_bad_attempts

        # The correct code is now rejected too.
        response = self._post_verify_email(email_code=correct_code)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.email_code_too_many_tries
        )

    def test_locked_state_blocks_new_code_until_expiry(self) -> None:
        self._post_email_address()
        for _ in range(self.app.conf.email_code_max_bad_attempts):
            self._post_verify_email(email_code="wrong-code")

        response = self._post_email_address()
        self._check_error_response(response, type_="POST_RESET_PASSWORD_FAIL", msg=ResetPwMsg.email_code_too_many_tries)

    def test_expired_locked_state_is_replaced_with_a_fresh_one(self) -> None:
        self.app.conf.throttle_resend = timedelta(0)
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        old_code = state.email_code.code

        for _ in range(self.app.conf.email_code_max_bad_attempts):
            self._post_verify_email(email_code="wrong-code")

        # Age the state past email_code_timeout
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        state.email_code.created_ts = utc_now() - (self.app.conf.email_code_timeout + timedelta(minutes=5))
        self.app.password_reset_state_db.save(state)

        response = self._post_email_address()
        self._check_success_response(response, msg=ResetPwMsg.reset_pw_initialized, type_="POST_RESET_PASSWORD_SUCCESS")

        fresh = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert fresh is not None
        assert fresh.bad_attempts == 0
        assert fresh.email_code.code != old_code

        # And the new code works.
        response = self._post_verify_email(email_code=fresh.email_code.code)
        self._check_success_response(response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_SUCCESS")

    def test_correct_code_does_not_increment_bad_attempts(self) -> None:
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None

        response = self._post_verify_email(email_code=state.email_code.code)
        self._check_success_response(response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_SUCCESS")

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        assert state.bad_attempts == 0

    def test_bad_attempts_counter_is_accurate_over_repeated_wrong_codes(self) -> None:
        """Each wrong code must advance the counter by exactly one, never more or fewer."""
        self.app.conf.email_code_max_bad_attempts = 5
        self._post_email_address()

        for expected in range(1, self.app.conf.email_code_max_bad_attempts + 1):
            response = self._post_verify_email(email_code="wrong-code")
            self._check_error_response(
                response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.state_not_found
            )
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
            assert state is not None
            assert state.bad_attempts == expected

    def test_wrong_code_answers_the_same_with_and_without_a_state(self) -> None:
        """Counting an attempt must not turn "a state exists" into a status-code oracle.

        The counter write is reachable only when a state exists and the code is wrong. If it
        could ever escape as an unhandled exception the caller would get a 500 there and a
        200 otherwise, which is exactly the distinguisher resolving by eppn removed.
        """
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        self.app.password_reset_state_db.remove_state(state)

        # Same session hint, but nothing to load and so no counter write.
        without_state = self._post_verify_email(email_code="wrong-code")

        self._post_email_address()
        assert self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn) is not None
        with_state = self._post_verify_email(email_code="wrong-code")

        assert without_state.status_code == 200
        assert with_state.status_code == 200
        for response in (without_state, with_state):
            self._check_error_response(
                response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.state_not_found
            )

    def test_counter_survives_upgrade_to_phone_state(self) -> None:
        """The counter must not reset when the state is upgraded to email-and-phone.

        Task 2's review flagged that nothing pinned this. It is not exploitable today,
        because reaching the upgrade requires an already-verified email code — an attacker
        without the code cannot trigger it. But the counter becomes load-bearing here, so
        pin it rather than rely on that argument holding after future edits.
        """
        self.mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms", return_value=True)
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None

        # Verify first - a correct code clears the counter, so a bad guess made before this
        # point would not survive to be observed. Then one bad guess to put the counter up.
        self._post_verify_email(email_code=state.email_code.code)
        self._post_verify_email(email_code="wrong-code")
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        assert state.bad_attempts == 1

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(state, ResetPasswordEmailState)
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        with self.app.test_request_context():
            state.extra_security = get_extra_security_alternatives(user)
            self.app.password_reset_state_db.save(state)
            send_verify_phone_code(state, state.extra_security["phone_numbers"][0]["number"])

        upgraded = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(upgraded, ResetPasswordEmailAndPhoneState)
        assert upgraded.bad_attempts == 1

    def test_downgrade_from_phone_state_carries_the_counter(self) -> None:
        """The phone-expiry branch rebuilds the state, which must not resurrect a stale counter.

        The rebuild is behind the code comparison, and a correct code clears the counter, so
        the value it carries over is always zero today. Pin that: if the rebuild ever wrote
        back the pre-comparison count instead, a user who just proved they hold the code would
        be handed their old strikes back at the exact moment the flow restarts.
        """
        self.mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms", return_value=True)
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        email_code = state.email_code.code

        self._post_verify_email(email_code=email_code)

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(state, ResetPasswordEmailState)
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        with self.app.test_request_context():
            state.extra_security = get_extra_security_alternatives(user)
            self.app.password_reset_state_db.save(state)
            send_verify_phone_code(state, state.extra_security["phone_numbers"][0]["number"])

        upgraded = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(upgraded, ResetPasswordEmailAndPhoneState)
        # Put strikes on the phone state out of band: every route to a non-zero counter here
        # runs through a correct code, which clears it.
        upgraded.bad_attempts = self.app.conf.email_code_max_bad_attempts - 1
        self.app.password_reset_state_db.save(upgraded)

        # Expire the phone code and submit the correct email code, which downgrades the state.
        self.app.conf.phone_code_timeout = timedelta(0)
        response = self._post_verify_email(email_code=email_code)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.expired_phone_code
        )

        downgraded = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(downgraded, ResetPasswordEmailState)
        assert not isinstance(downgraded, ResetPasswordEmailAndPhoneState)
        # Cleared by the correct code, and the rebuild carried the cleared value, not the
        # stale one it was loaded with.
        assert downgraded.bad_attempts == 0

    def _post_extra_security_phone(self, email_code: str, phone_index: int = 0) -> TestResponse:
        """POST a code to /extra-security-phone/ reusing the session from earlier requests."""
        with self.app.test_request_context():
            url = url_for("reset_password.choose_extra_security_phone", _external=True)
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = {"email_code": email_code, "phone_index": str(phone_index), "csrf_token": csrf_token}
            return c.post(url, data=json.dumps(data), content_type=self.content_type_json)

    def test_correct_code_clears_bad_attempts(self) -> None:
        """Proving possession of the code hands the user their full budget of attempts back.

        This is what keeps a legitimate user's typos from adding up across the flow, and it is
        safe precisely because it sits behind the comparison: a guess that does not match the
        code never reaches it, so no attacker can refill their own budget.
        """
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        correct_code = state.email_code.code

        for expected in range(1, self.app.conf.email_code_max_bad_attempts):
            self._check_error_response(
                self._post_verify_email(email_code="wrong-code"),
                type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL",
                msg=ResetPwMsg.state_not_found,
            )
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
            assert state is not None
            assert state.bad_attempts == expected

        self._check_success_response(
            self._post_verify_email(email_code=correct_code), type_="POST_RESET_PASSWORD_VERIFY_EMAIL_SUCCESS"
        )
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        assert state.bad_attempts == 0

    def test_verified_user_is_not_locked_out_downstream(self) -> None:
        """Typos after the code has been proven must not end the recovery.

        Every view charges a wrong code against the same counter, and three strikes lock the
        state until it expires. Without the counter being cleared on a correct code, a user
        who mistyped twice before getting it right would have a single strike left to cover
        the whole rest of the flow.
        """
        self.mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms", return_value=True)
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        correct_code = state.email_code.code

        # Two typos, then the correct code.
        for _ in range(self.app.conf.email_code_max_bad_attempts - 1):
            self._post_verify_email(email_code="wrong-code")
        self._check_success_response(
            self._post_verify_email(email_code=correct_code), type_="POST_RESET_PASSWORD_VERIFY_EMAIL_SUCCESS"
        )
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        assert state.bad_attempts == 0

        # Two more typos further along the flow. These do count - metering every view is what
        # makes the cap mean anything - but the budget was refilled, so nothing locks.
        for expected in range(1, self.app.conf.email_code_max_bad_attempts):
            self._check_error_response(
                self._post_extra_security_phone(email_code="wrong-code"),
                type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
                msg=ResetPwMsg.state_not_found,
            )
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
            assert state is not None
            assert state.bad_attempts == expected

        # And the flow completes, with the counter cleared again on the way through.
        self._check_success_response(
            self._post_extra_security_phone(email_code=correct_code),
            type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_SUCCESS",
            msg=ResetPwMsg.send_sms_success,
        )
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        assert state.bad_attempts == 0

    def _post_after_verification_view(self, endpoint: str, payload: dict[str, Any]) -> TestResponse:
        """POST to one of the five views that run after /verify-email/, reusing self.browser."""
        with self.app.test_request_context():
            url = url_for(endpoint, _external=True)
        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = dict(payload, csrf_token=csrf_token)
            return c.post(url, data=json.dumps(data), content_type=self.content_type_json)

    @staticmethod
    def _post_verification_views(email_code: str) -> list[tuple[str, dict[str, Any], str]]:
        """The five views that run after /verify-email/, with a body each of them accepts.

        Bodies that pass schema validation, so the request reaches the view rather than being
        turned back by @UnmarshalWith - otherwise a test of the view's own guard would prove
        nothing about the view.
        """
        password = "T%7j 8/tT a0=b"
        return [
            (
                "reset_password.set_new_pw_no_extra_security",
                {"email_code": email_code, "password": password},
                "POST_RESET_PASSWORD_NEW_PASSWORD_FAIL",
            ),
            (
                "reset_password.choose_extra_security_phone",
                {"email_code": email_code, "phone_index": 0},
                "POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            ),
            (
                "reset_password.set_new_pw_extra_security_phone",
                {"email_code": email_code, "password": password, "phone_code": "123456"},
                "POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            ),
            (
                "reset_password.set_new_pw_extra_security_key",
                {"email_code": email_code, "password": password, "webauthn_response": SAMPLE_WEBAUTHN_REQUEST},
                "POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_FAIL",
            ),
            (
                "reset_password.set_new_pw_extra_security_external_mfa",
                {"email_code": email_code, "password": password},
                "POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_EXTERNAL_MFA_FAIL",
            ),
        ]

    def test_post_verification_views_require_a_verified_session(self) -> None:
        """Every view after /verify-email/ refuses a session that never supplied the code.

        The session used here is exactly what start_reset_pw leaves behind: the address the
        caller typed, and no eppn. A captcha is the only thing standing between anyone and
        that session, so it must not be able to resolve a state - not even holding the
        correct code. And because the guard runs before any lookup, the counter must not move.
        """
        # Mocked so that, if a view did resolve the state, the reset would go through cleanly
        # and be caught by the assertions below rather than by a connection error.
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        self.mocker.patch("eduid.webapp.common.authn.vccs.get_vccs_client", return_value=MockVCCSClient())
        self.mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms", return_value=True)
        mock_request_user_sync.side_effect = self.request_user_sync

        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        correct_code = state.email_code.code

        with self.session_cookie_anon(self.browser) as c:
            with c.session_transaction() as sess:
                assert sess.common.eppn is None
                assert sess.reset_password.email.address == state.email_address

        for endpoint, payload, type_ in self._post_verification_views(correct_code):
            response = self._post_after_verification_view(endpoint, payload)
            self._check_error_response(response, type_=type_, msg=ResetPwMsg.invalid_session)
            after = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
            assert after is not None, f"{endpoint} removed the state"
            assert after.bad_attempts == 0, f"{endpoint} touched the attempt counter"
            assert after.email_code.is_verified is False, f"{endpoint} verified the state"
            assert isinstance(after, ResetPasswordEmailState), f"{endpoint} upgraded the state"

        # Nothing was reset: an unverified reset would have unverified all of this.
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        assert len(user.phone_numbers.verified) == 1
        assert len(user.identities.verified) == 3

    def test_attacker_with_a_captcha_cannot_reach_a_victims_state(self) -> None:
        """The account takeover this guard closes, end to end.

        start_reset_pw asks for a completed captcha and nothing else, reuses any live state
        for the address it is given, and writes that address into the caller's session. That
        used to be enough for the views downstream to resolve the victim's state, so an
        attacker could work from their own session and guess codes at /new-password/.
        """
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        self.mocker.patch("eduid.webapp.common.authn.vccs.get_vccs_client", return_value=MockVCCSClient())
        mock_request_user_sync.side_effect = self.request_user_sync
        assert self.test_user.mail_addresses.primary is not None
        victim_email = self.test_user.mail_addresses.primary.email

        # The victim starts a reset, verifies the code, then abandons the browser.
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        victim_code = state.email_code.code
        self._check_success_response(
            self._post_verify_email(email_code=victim_code), type_="POST_RESET_PASSWORD_VERIFY_EMAIL_SUCCESS"
        )

        with self.app.test_request_context():
            new_password_url = url_for("reset_password.set_new_pw_no_extra_security", _external=True)

        # A separate client, carrying no cookie from anything above.
        attacker = cast(CSRFTestClient, self.app.test_client())
        with self.session_cookie_anon(attacker) as c:
            response = c.get("/", content_type=self.content_type_json)
            with c.session_transaction() as sess:
                sess.reset_password.captcha.completed = True
            data: dict[str, Any] = {
                "email": victim_email,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
            }
            assert c.post("/", data=json.dumps(data), content_type=self.content_type_json).status_code == 200

            # A captcha bought the attacker the victim's address in their own session.
            with c.session_transaction() as sess:
                assert sess.reset_password.email.address == victim_email
                assert sess.common.eppn is None

            # Both a guess and the real code, since the point is that neither is even compared.
            for guess in ("wrong-code", victim_code):
                with c.session_transaction() as sess:
                    csrf_token = sess.get_csrf_token()
                data = {"email_code": guess, "password": "T%7j 8/tT a0=b", "csrf_token": csrf_token}
                self._check_error_response(
                    c.post(new_password_url, data=json.dumps(data), content_type=self.content_type_json),
                    type_="POST_RESET_PASSWORD_NEW_PASSWORD_FAIL",
                    msg=ResetPwMsg.invalid_session,
                )

        # The victim's state was never reached: no strike for the wrong guess, and the state
        # is still there rather than consumed by a reset.
        after = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert after is not None
        assert after.bad_attempts == 0
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        assert len(user.identities.verified) == 3

    def test_wrong_code_on_verify_email_is_counted_even_after_verification(self) -> None:
        """/verify-email/ keeps counting for the whole life of the state.

        It is the view an attacker guesses against, so opting it out at any point - including
        once the state has been verified by someone else's successful call - would reopen the
        brute force this branch closed.
        """
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None

        self._check_success_response(
            self._post_verify_email(email_code=state.email_code.code),
            type_="POST_RESET_PASSWORD_VERIFY_EMAIL_SUCCESS",
        )
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        assert state.email_code.is_verified is True
        assert state.bad_attempts == 0

        self._check_error_response(
            self._post_verify_email(email_code="wrong-code"),
            type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL",
            msg=ResetPwMsg.state_not_found,
        )
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        assert state.bad_attempts == 1

    def test_wrong_code_on_a_verified_session_still_locks_the_state(self) -> None:
        """Metering does not stop once the session is verified.

        A verified session is one browser's proof, not a licence to grind the code. Guesses
        made through it keep costing a strike, and the cap still lands.
        """
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        correct_code = state.email_code.code
        self._check_success_response(
            self._post_verify_email(email_code=correct_code), type_="POST_RESET_PASSWORD_VERIFY_EMAIL_SUCCESS"
        )

        for expected in range(1, self.app.conf.email_code_max_bad_attempts + 1):
            self._check_error_response(
                self._post_extra_security_phone(email_code="wrong-code"),
                type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
                msg=ResetPwMsg.state_not_found,
            )
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
            assert state is not None
            assert state.bad_attempts == expected

        # The cap is reached, so guessing stops there - and so does the correct code.
        for code in ("wrong-code", correct_code):
            self._check_error_response(
                self._post_extra_security_phone(email_code=code),
                type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
                msg=ResetPwMsg.email_code_too_many_tries,
            )

    def test_locked_state_is_rejected_by_a_post_verification_view(self) -> None:
        """The lockout check runs on every view, ahead of the comparison."""
        self._post_email_address()
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        correct_code = state.email_code.code

        self._check_success_response(
            self._post_verify_email(email_code=correct_code), type_="POST_RESET_PASSWORD_VERIFY_EMAIL_SUCCESS"
        )

        # Lock the state out of band, so the lockout is the only thing under test here.
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        state.bad_attempts = self.app.conf.email_code_max_bad_attempts
        self.app.password_reset_state_db.save(state)

        # Even the correct code is refused, and it does not clear the counter on its way out.
        self._check_error_response(
            self._post_extra_security_phone(email_code=correct_code),
            type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            msg=ResetPwMsg.email_code_too_many_tries,
        )
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state is not None
        assert state.bad_attempts == self.app.conf.email_code_max_bad_attempts

    def test_config_rejects_a_zero_bad_attempt_cap(self) -> None:
        """email_code_max_bad_attempts=0 would lock every state on first contact (0 >= 0)."""
        with pytest.raises(ValidationError):
            self.app.conf.email_code_max_bad_attempts = 0
        with pytest.raises(ValidationError):
            self.app.conf.email_code_length = 0

    def test_post_reset_wrong_csrf(self) -> None:
        data2 = {"csrf_token": "wrong-code"}
        response = self._post_reset_code(data2=data2)
        assert response is not None
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    def test_post_reset_other_user_session_eppn(self) -> None:
        if self.test_user.mail_addresses.primary is None:
            raise RuntimeError(f"user {self.test_user} has no primary email address")

        # Request reset password email for test_user using other_test_user session
        with self.app.test_request_context():
            request_url = url_for("reset_password.start_reset_pw", _external=True)
        with self.session_cookie(self.browser, eppn=self.other_test_user.eppn) as c:
            response = c.get("/", content_type=self.content_type_json)
            # complete captcha
            self._get_captcha()
            self._captcha()
            data = {
                "email": self.test_user.mail_addresses.primary.email,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
            }
            response = c.post(request_url, data=json.dumps(data), content_type=self.content_type_json)

        # Try to verify email code for test_user using other_test_user session
        with self.app.test_request_context():
            verify_url = url_for("reset_password.verify_email", _external=True)
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state
        with self.session_cookie(self.browser, eppn=self.other_test_user.eppn) as c:
            data = {
                "email_code": state.email_code.code,
                "csrf_token": self.get_response_payload(response)["csrf_token"],
            }
            response = c.post(verify_url, data=json.dumps(data), content_type=self.content_type_json)

        # Resolution is keyed on the session eppn (other_test_user), which has no reset
        # state, so the foreign session learns nothing about the code's validity.
        self._check_error_response(
            response=response, type_="POST_RESET_PASSWORD_VERIFY_EMAIL_FAIL", msg=ResetPwMsg.state_not_found
        )

    def test_post_reset_password(self) -> None:
        response = self._post_reset_password()
        self._check_success_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_SUCCESS", msg=ResetPwMsg.pw_reset_success
        )

        # check that the user no longer has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        assert len(verified_phone_numbers) == 0
        verified_identities = user.identities.verified
        assert len(verified_identities) == 0

        # check that the password is marked as generated
        password = user.credentials.to_list()[0]
        assert isinstance(password, Password)
        assert password.is_generated

    def test_post_reset_password_no_data(self) -> None:
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

    def test_post_reset_password_weak(self) -> None:
        data2 = {"password": "pw"}
        response = self._post_reset_password(data2=data2)
        self._check_error_response(response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_FAIL", msg=ResetPwMsg.resetpw_weak)

    def test_post_reset_password_no_csrf(self) -> None:
        data2 = {"csrf_token": ""}
        response = self._post_reset_password(data2=data2)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_FAIL",
            error={
                "csrf_token": ["CSRF failed to validate"],
            },
        )

    def test_post_reset_password_wrong_code(self) -> None:
        data2 = {"email_code": "wrong-code"}
        response = self._post_reset_password(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_FAIL", msg=ResetPwMsg.state_not_found
        )

        # check that the user still has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        assert len(verified_phone_numbers) == 1
        verified_identities = user.identities.verified
        assert len(verified_identities) == 3

    def test_post_reset_password_custom(self) -> None:
        data2 = {"password": "cust0m-p4ssw0rd"}
        response = self._post_reset_password(data2=data2)
        self._check_success_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_SUCCESS", msg=ResetPwMsg.pw_reset_success
        )

        user = self.app.private_userdb.get_user_by_eppn(self.test_user.eppn)
        password = user.credentials.to_list()[0]
        assert isinstance(password, Password)
        assert not password.is_generated

    def test_post_choose_extra_sec(self) -> None:
        response = self._post_choose_extra_sec()
        self._check_success_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_SUCCESS", msg=ResetPwMsg.send_sms_success
        )

    def test_post_choose_extra_sec_sms_fail(self) -> None:
        self.app.conf.throttle_sms = timedelta(seconds=300)
        from eduid.common.rpc.exceptions import MsgTaskFailed

        response = self._post_choose_extra_sec(sendsms_side_effect=MsgTaskFailed())
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.send_sms_failure
        )

    def test_post_choose_extra_sec_throttled(self) -> None:
        self.app.conf.throttle_sms = datetime.timedelta(minutes=5)
        response = self._post_choose_extra_sec(repeat=True)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.send_sms_throttled
        )

    def test_post_choose_extra_sec_not_throttled(self) -> None:
        self.app.conf.throttle_sms = timedelta(0)
        response = self._post_choose_extra_sec(repeat=True)
        self._check_success_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_SUCCESS", msg=ResetPwMsg.send_sms_success
        )

    def test_post_choose_extra_sec_wrong_code(self) -> None:
        """A failed /verify-email/ leaves no verified session, so the next view refuses outright.

        data2 is the code sent to /verify-email/, so this arrives at /extra-security-phone/
        with the correct code but nothing to show it was ever proven. That used to resolve the
        state anyway - through the address start_reset_pw put in the session - and answer
        email-not-validated, which told the caller their code was right.
        """
        data2 = {"email_code": "wrong-code"}
        response = self._post_choose_extra_sec(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.invalid_session
        )

    def test_post_choose_extra_sec_bad_phone_index(self) -> None:
        data3 = {"phone_index": "3"}
        response = self._post_choose_extra_sec(data3=data3)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.unknown_phone_number
        )

    def test_post_choose_extra_sec_wrong_csrf_token(self) -> None:
        data3 = {"csrf_token": "wrong-token"}
        response = self._post_choose_extra_sec(data3=data3)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    def test_post_choose_extra_sec_wrong_final_code(self) -> None:
        data3 = {"email_code": "wrong-code"}
        response = self._post_choose_extra_sec(data3=data3)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.state_not_found
        )

    def test_post_reset_password_secure_phone(self) -> None:
        response = self._post_reset_password_secure_phone()
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_SUCCESS",
            msg=ResetPwMsg.pw_reset_success,
        )

        # check that the user still has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        assert len(verified_phone_numbers) == 1
        verified_identities = user.identities.verified
        assert len(verified_identities) == 3

    def test_post_reset_password_secure_phone_verify_fail(self) -> None:
        self.mocker.patch("eduid.webapp.reset_password.views.reset_password.verify_phone_number", return_value=False)
        response = self._post_reset_password_secure_phone()
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.phone_invalid
        )

    def test_post_reset_password_secure_phone_wrong_csrf_token(self) -> None:
        data2 = {"csrf_token": "wrong-code"}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    def test_post_reset_password_secure_phone_wrong_email_code(self) -> None:
        data2 = {"email_code": "wrong-code"}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.state_not_found
        )

    def test_post_reset_password_secure_phone_wrong_sms_code(self) -> None:
        data2 = {"phone_code": "wrong-code"}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            msg=ResetPwMsg.unknown_phone_code,
        )

    def test_post_reset_password_secure_phone_non_ascii_sms_code(self) -> None:
        """A non-ASCII phone code is just a wrong code, not a TypeError out of compare_digest."""
        data2 = {"phone_code": "åäö123"}
        response = self._post_reset_password_secure_phone(data2=data2)
        assert response.status_code == 200
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            msg=ResetPwMsg.unknown_phone_code,
        )

    def test_post_reset_password_secure_phone_weak_password(self) -> None:
        data2 = {"password": "pw"}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL", msg=ResetPwMsg.resetpw_weak
        )

    def test_post_reset_password_security_key(self) -> None:
        response = self._post_reset_password_security_key()
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_SUCCESS",
            msg=ResetPwMsg.pw_reset_success,
        )

        # check that the user still has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        assert len(verified_phone_numbers) == 1
        verified_identities = user.identities.verified
        assert len(verified_identities) == 3

    def test_post_reset_password_security_key_custom_pw(self) -> None:
        response = self._post_reset_password_security_key(custom_password="T%7j 8/tT a0=b")
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_SUCCESS",
            msg=ResetPwMsg.pw_reset_success,
        )
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        for cred in user.credentials.filter(Password):
            assert not cred.is_generated

    def test_post_reset_password_security_key_no_data(self) -> None:
        response = self._post_reset_password_security_key(data2={})
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_FAIL",
            error={
                "email_code": ["Missing data for required field."],
                "csrf_token": ["Missing data for required field."],
                "password": ["Missing data for required field."],
            },
        )

    def test_post_reset_password_security_key_wrong_credential(self) -> None:
        credential_data = {
            "credential_data": "AAAAAAAAAAAAAAAAAAAAAABAi3KjBT0t5TPm693T0O0f4zyiwvdu9cY8BegCjiVvq_FS-ZmPcvXipFvHv"
            "D5CH6ZVRR3nsVsOla0Cad3fbtUA_aUBAgMmIAEhWCCiwDYGxl1LnRMqooWm0aRR9YbBG2LZ84BMNh_4rHkA9yJYIIujMrUOpGekb"
            "XjgMQ8M13ZsBD_cROSPB79eGz2Nw1ZE"
        }
        response = self._post_reset_password_security_key(credential_data=credential_data)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_FAIL", msg=ResetPwMsg.fido_token_fail
        )

    def test_post_reset_password_security_key_wrong_request(self) -> None:
        data2 = {"webauthn_response": copy.deepcopy(SAMPLE_WEBAUTHN_REQUEST)}
        assert isinstance(data2["webauthn_response"], dict)
        assert isinstance(data2["webauthn_response"]["response"], dict)
        data2["webauthn_response"]["response"]["authenticatorData"] = (
            "Wrong-authenticatorData----UMmBLDxB7n3apMPQAAAAAAA"
        )
        response = self._post_reset_password_security_key(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_FAIL", msg=ResetPwMsg.fido_token_fail
        )

    def test_post_reset_password_security_key_wrong_csrf(self) -> None:
        data2 = {"csrf_token": "wrong-code"}
        response = self._post_reset_password_security_key(data2=data2)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    def test_post_reset_password_security_key_wrong_code(self) -> None:
        data2 = {"email_code": "wrong-code"}
        response = self._post_reset_password_security_key(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_FAIL", msg=ResetPwMsg.state_not_found
        )

    def test_post_reset_password_security_key_weak_password(self) -> None:
        data2 = {"password": "pw"}
        response = self._post_reset_password_security_key(data2=data2)
        self._check_error_response(
            response, type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_TOKEN_FAIL", msg=ResetPwMsg.resetpw_weak
        )

    def test_post_reset_password_secure_external_mfa(self) -> None:
        response = self._post_reset_password_secure_external_mfa()
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_EXTERNAL_MFA_SUCCESS",
            msg=ResetPwMsg.pw_reset_success,
        )

        # check that the user still has verified data
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        verified_phone_numbers = user.phone_numbers.verified
        assert len(verified_phone_numbers) == 1
        verified_identities = user.identities.verified
        assert len(verified_identities) == 3

    def test_post_reset_password_secure_external_mfa_no_mfa_auth(self) -> None:
        external_mfa_state = {"success": False, "issuer": None}
        response = self._post_reset_password_secure_external_mfa(external_mfa_state=external_mfa_state)
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_EXTERNAL_MFA_FAIL",
            msg=ResetPwMsg.external_mfa_fail,
        )

    def test_post_reset_password_secure_email_timeout(self) -> None:
        self.app.conf.email_code_timeout = timedelta(0)
        response = self._post_reset_password_secure_phone()
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            msg=ResetPwMsg.expired_email_code,
        )

    def test_post_reset_password_secure_phone_timeout(self) -> None:
        self.app.conf.phone_code_timeout = timedelta(0)
        response = self._post_reset_password_secure_phone()
        self._check_error_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_FAIL",
            msg=ResetPwMsg.expired_phone_code,
        )

    def test_post_reset_password_secure_phone_custom(self) -> None:
        data2 = {"password": "other-password"}
        response = self._post_reset_password_secure_phone(data2=data2)
        self._check_success_response(
            response,
            type_="POST_RESET_PASSWORD_NEW_PASSWORD_EXTRA_SECURITY_PHONE_SUCCESS",
            msg=ResetPwMsg.pw_reset_success,
        )

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user.eppn)
        password = user.credentials.to_list()[0]
        assert isinstance(password, Password)
        assert not password.is_generated

    def test_revoke_termination_on_password_reset(self) -> None:
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

    def test_get_code_backdoor(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        resp = self._get_email_code_backdoor()

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert state

        assert resp.status_code == 200
        assert resp.data == state.email_code.code.encode("ascii")

    def test_get_code_no_backdoor_in_pro(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("production")

        resp = self._get_email_code_backdoor()

        assert resp.status_code == 400

    def test_get_code_no_backdoor_misconfigured1(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = ""
        self.app.conf.environment = EduidEnvironment("dev")

        resp = self._get_email_code_backdoor(magic_cookie_name="wrong_name")

        assert resp.status_code == 400

    def test_get_code_no_backdoor_misconfigured2(self) -> None:
        self.app.conf.magic_cookie = ""
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        resp = self._get_email_code_backdoor()

        assert resp.status_code == 400

    def test_get_phone_code_backdoor(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        resp = self._get_phone_code_backdoor()

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user.eppn)
        assert isinstance(state, ResetPasswordEmailAndPhoneState)

        assert resp.status_code == 200
        assert resp.data == state.phone_code.code.encode("ascii")

    def test_get_phone_code_no_backdoor_in_pro(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("production")

        resp = self._get_phone_code_backdoor()

        assert resp.status_code == 400

    def test_get_phone_code_no_backdoor_misconfigured1(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = ""
        self.app.conf.environment = EduidEnvironment("dev")

        resp = self._get_phone_code_backdoor(magic_cookie_name="wrong_name")

        assert resp.status_code == 400

    def test_get_phone_code_no_backdoor_misconfigured2(self) -> None:
        self.app.conf.magic_cookie = ""
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        resp = self._get_phone_code_backdoor()

        assert resp.status_code == 400
