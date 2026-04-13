import json
from collections.abc import Mapping
from datetime import timedelta
from typing import Any
from urllib.parse import quote_plus

import pytest
from pytest_mock import MockerFixture
from werkzeug.test import TestResponse

from eduid.common.config.base import EduidEnvironment
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.phone.app import PhoneApp, phone_init_app
from eduid.webapp.phone.helpers import PhoneMsg


class PhoneTests(EduidAPITestCase[PhoneApp]):
    copy_user_to_private = True

    @pytest.fixture(autouse=True)
    def setup(self, setup_api: None, mocker: MockerFixture) -> None:
        self.mocker = mocker
        self.test_number = "+34609609609"

    def load_app(self, config: Mapping[str, Any]) -> PhoneApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return phone_init_app("testing", config)

    @pytest.fixture(scope="class")
    def update_config(self) -> dict[str, Any]:
        config = self._get_base_config()
        config.update(
            {
                "available_languages": {"en": "English", "sv": "Svenska"},
                "phone_verification_timeout": 7200,
                "default_country_code": "46",
                "throttle_resend_seconds": 300,
            }
        )
        return config

    # parameterized test methods

    def _get_all_phone(self, eppn: str | None = None) -> dict[str, Any]:
        """
        GET all phone data for some user

        :param eppn: eppn for the user
        """
        response = self.browser.get("/all")
        assert response.status_code == 401

        eppn = eppn or self.test_user_data["eduPersonPrincipalName"]
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get("/all")

            return json.loads(response2.data)

    def _post_phone(
        self,
        mod_data: dict[str, Any] | None = None,
        send_data: bool = True,
    ) -> TestResponse:
        """
        POST phone data to add a new phone number to the test user

        :param mod_data: to control what data is POSTed
        :param send_data: whether to POST any data at all
        """
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_code_verification = self.mocker.patch("eduid.webapp.phone.verifications.get_short_hash")
        mock_phone_validator = self.mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms")
        mock_phone_validator.return_value = True
        mock_code_verification.return_value = "5250f9a4"
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data["eduPersonPrincipalName"]

        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "number": "+34670123456",
                        "verified": False,
                        "primary": False,
                        "csrf_token": sess.get_csrf_token(),
                    }
                if mod_data:
                    data.update(mod_data)

                if send_data:
                    return client.post("/new", data=json.dumps(data), content_type=self.content_type_json)

                return client.post("/new")

    def _post_primary(self, mod_data: dict[str, Any] | None = None) -> TestResponse:
        """
        Set phone number as the primary number for the test user

        :param mod_data: to control what data is POSTed
        """
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self.browser.post("/primary")
        assert response.status_code == 401

        eppn = self.test_user_data["eduPersonPrincipalName"]

        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"number": self.test_number, "csrf_token": sess.get_csrf_token()}
                if mod_data:
                    data.update(mod_data)

            return client.post("/primary", data=json.dumps(data), content_type=self.content_type_json)

    def _remove(self, mod_data: dict[str, Any] | None = None) -> TestResponse:
        """
        Remove phone number from the test user

        :param mod_data: to control what data is POSTed
        """
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self.browser.post("/remove")
        assert response.status_code == 401

        eppn = self.test_user_data["eduPersonPrincipalName"]

        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"number": self.test_number, "csrf_token": sess.get_csrf_token()}
                if mod_data:
                    data.update(mod_data)

            return client.post("/remove", data=json.dumps(data), content_type=self.content_type_json)

    def _send_code(
        self,
        mod_data: dict[str, Any] | None = None,
        captcha_completed: bool = True,
    ) -> TestResponse:
        """
        Send a POST request to trigger re-sending a verification code for an unverified phone number in the test user.

        :param mod_data: to control the data to be POSTed
        """
        mock_verification_code = self.mocker.patch("eduid.webapp.phone.verifications.get_short_hash")
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_phone_validator = self.mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms")
        mock_phone_validator.return_value = True
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_verification_code.return_value = "5250f9a4"

        eppn = self.test_user_data["eduPersonPrincipalName"]

        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"number": self.test_number, "csrf_token": sess.get_csrf_token()}
                    if captcha_completed:
                        sess.phone.captcha.completed = True
                if mod_data:
                    data.update(mod_data)

            return client.post("/send-code", data=json.dumps(data), content_type=self.content_type_json)

    def _get_code_backdoor(
        self,
        mod_data: dict[str, Any] | None = None,
        phone: str = "+34670123456",
        code: str = "5250f9a4",
        magic_cookie_name: str | None = None,
    ) -> TestResponse:
        """
        POST phone data to generate a verification state,
        and try to get the generated code through the backdoor

        :param mod_data: to control what data is POSTed
        :param phone: the phone to use
        :param code: mock verification code
        """
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_code_verification = self.mocker.patch("eduid.webapp.phone.verifications.get_short_hash")
        mock_phone_validator = self.mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms")
        mock_phone_validator.return_value = True
        mock_code_verification.return_value = code
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data["eduPersonPrincipalName"]

        with self.session_cookie_and_magic_cookie(
            self.browser, eppn=eppn, magic_cookie_name=magic_cookie_name
        ) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data: dict[str, Any] = {
                        "number": phone,
                        "verified": False,
                        "primary": False,
                        "csrf_token": sess.get_csrf_token(),
                    }
                if mod_data:
                    data.update(mod_data)

                client.post("/new", data=json.dumps(data), content_type=self.content_type_json)

                with client.session_transaction() as sess:
                    sess.phone.captcha.completed = True
                    sess.persist()
                    data2: dict[str, Any] = {
                        "number": phone,
                        "csrf_token": sess.get_csrf_token(),
                    }

                    client.post("/send-code", data=json.dumps(data2), content_type=self.content_type_json)

                phone = quote_plus(phone)
                eppn = quote_plus(eppn)

                return client.get(f"/get-code?phone={phone}&eppn={eppn}")

    # actual tests

    def test_get_all_phone(self) -> None:
        phone_data = self._get_all_phone()

        assert phone_data["type"] == "GET_PHONE_ALL_SUCCESS"
        assert phone_data["payload"]["csrf_token"] is not None
        assert self.test_number == phone_data["payload"]["phones"][0].get("number")
        assert phone_data["payload"]["phones"][0].get("primary")
        assert phone_data["payload"]["phones"][1].get("number") == "+34 6096096096"
        assert not phone_data["payload"]["phones"][1].get("primary")

    def test_post_phone_error_no_data(self) -> None:
        response = self._post_phone(send_data=False)
        new_phone_data = json.loads(response.data)
        assert new_phone_data["type"] == "POST_PHONE_NEW_FAIL"

    def test_post_phone_country_code(self) -> None:
        response = self.browser.post("/new")
        assert response.status_code == 401

        response = self._post_phone()

        assert response.status_code == 200
        new_phone_data = json.loads(response.data)

        assert new_phone_data["type"] == "POST_PHONE_NEW_SUCCESS"
        assert new_phone_data["payload"]["phones"][2].get("number") == "+34670123456"
        assert not new_phone_data["payload"]["phones"][2].get("verified")

    def test_post_phone_no_country_code(self) -> None:
        data = {"number": "0701234565"}
        response = self._post_phone(mod_data=data)

        assert response.status_code == 200
        new_phone_data = json.loads(response.data)

        assert new_phone_data["type"] == "POST_PHONE_NEW_SUCCESS"
        assert new_phone_data["payload"]["phones"][2].get("number") == "+46701234565"
        assert not new_phone_data["payload"]["phones"][2].get("verified")

    def test_post_phone_wrong_csrf(self) -> None:
        data = {"csrf_token": "wrong-token"}
        response = self._post_phone(mod_data=data)

        assert response.status_code == 200
        new_phone_data = json.loads(response.data)

        assert new_phone_data["type"] == "POST_PHONE_NEW_FAIL"
        assert new_phone_data["payload"]["error"]["csrf_token"] == ["CSRF failed to validate"]

    def test_post_phone_invalid(self) -> None:
        data = {"number": "0"}
        response = self._post_phone(mod_data=data)

        assert response.status_code == 200
        new_phone_data = json.loads(response.data)

        assert new_phone_data["type"] == "POST_PHONE_NEW_FAIL"
        assert new_phone_data["payload"]["error"]["number"] == ["phone.phone_format"]

    def test_post_phone_as_verified(self) -> None:
        data = {"verified": True}
        response = self._post_phone(mod_data=data)

        assert response.status_code == 200
        new_phone_data = json.loads(response.data)

        assert new_phone_data["type"] == "POST_PHONE_NEW_SUCCESS"
        assert new_phone_data["payload"]["phones"][2].get("number") == "+34670123456"
        assert not new_phone_data["payload"]["phones"][2].get("verified")
        assert not new_phone_data["payload"]["phones"][2].get("primary")

    def test_post_phone_as_primary(self) -> None:
        data = {"primary": True}
        response = self._post_phone(mod_data=data)

        assert response.status_code == 200
        new_phone_data = json.loads(response.data)

        assert new_phone_data["type"] == "POST_PHONE_NEW_SUCCESS"
        assert new_phone_data["payload"]["phones"][2].get("number") == "+34670123456"
        assert not new_phone_data["payload"]["phones"][2].get("verified")
        assert not new_phone_data["payload"]["phones"][2].get("primary")

    def test_post_phone_bad_swedish_mobile(self) -> None:
        data = {"number": "0711234565"}
        response = self._post_phone(mod_data=data)

        assert response.status_code == 200
        new_phone_data = json.loads(response.data)

        assert new_phone_data["type"] == "POST_PHONE_NEW_FAIL"
        assert new_phone_data["payload"]["error"].get("number") == ["phone.swedish_mobile_format"]

    def test_post_phone_bad_country_code(self) -> None:
        data = {"number": "00711234565"}
        response = self._post_phone(mod_data=data)

        assert response.status_code == 200
        new_phone_data = json.loads(response.data)

        assert new_phone_data["type"] == "POST_PHONE_NEW_FAIL"
        assert new_phone_data["payload"]["error"].get("_schema") == ["phone.e164_format"]

    def test_post_primary(self) -> None:
        response = self._post_primary()

        assert response.status_code == 200
        new_phone_data = json.loads(response.data)

        assert new_phone_data["type"] == "POST_PHONE_PRIMARY_SUCCESS"
        assert new_phone_data["payload"]["phones"][0]["verified"]
        assert new_phone_data["payload"]["phones"][0]["primary"]
        assert self.test_number == new_phone_data["payload"]["phones"][0]["number"]
        assert not new_phone_data["payload"]["phones"][1]["verified"]
        assert not new_phone_data["payload"]["phones"][1]["primary"]
        assert new_phone_data["payload"]["phones"][1]["number"] == "+34 6096096096"

    def test_post_primary_no_csrf(self) -> None:
        data = {"csrf_token": ""}
        response = self._post_primary(mod_data=data)

        assert response.status_code == 200
        new_phone_data = json.loads(response.data)

        assert new_phone_data["type"] == "POST_PHONE_PRIMARY_FAIL"
        assert new_phone_data["payload"]["error"]["csrf_token"] == ["CSRF failed to validate"]

    def test_post_primary_unknown(self) -> None:
        data = {"number": "+66666666666"}
        response = self._post_primary(mod_data=data)

        assert response.status_code == 200
        new_phone_data = json.loads(response.data)

        assert new_phone_data["type"] == "POST_PHONE_PRIMARY_FAIL"
        assert PhoneMsg.unknown_phone.value == new_phone_data["payload"]["message"]

    def test_remove(self) -> None:
        response = self._remove()

        assert response.status_code == 200

        delete_phone_data = json.loads(response.data)

        assert delete_phone_data["type"] == "POST_PHONE_REMOVE_SUCCESS"
        assert delete_phone_data["payload"]["phones"][0].get("number") == "+34 6096096096"

    def test_remove_primary_other_unverified(self) -> None:
        data = {"number": "+34 6096096096"}
        response = self._remove(mod_data=data)

        assert response.status_code == 200

        delete_phone_data = json.loads(response.data)

        assert delete_phone_data["type"] == "POST_PHONE_REMOVE_SUCCESS"
        assert self.test_number == delete_phone_data["payload"]["phones"][0].get("number")

    def test_remove_no_csrf(self) -> None:
        data = {"csrf_token": ""}
        response = self._remove(mod_data=data)

        assert response.status_code == 200

        delete_phone_data = json.loads(response.data)

        assert delete_phone_data["type"] == "POST_PHONE_REMOVE_FAIL"
        assert delete_phone_data["payload"]["error"]["csrf_token"] == ["CSRF failed to validate"]

    def test_remove_unknown(self) -> None:
        data = {"number": "+33333333333"}
        response = self._remove(mod_data=data)

        assert response.status_code == 200

        delete_phone_data = json.loads(response.data)

        assert delete_phone_data["type"] == "POST_PHONE_REMOVE_FAIL"
        assert delete_phone_data["payload"]["message"] == "phones.unknown_phone"

    def test_remove_primary_other_verified(self, mocker: MockerFixture) -> None:
        mock_request_user_sync = mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_code_verification = mocker.patch("eduid.webapp.phone.verifications.get_short_hash")
        mock_phone_validator = mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms")
        mock_phone_validator.return_value = True
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_code_verification.return_value = "12345"

        response = self.browser.post("/remove")
        assert response.status_code == 401

        eppn = self.test_user_data["eduPersonPrincipalName"]
        phone = "+34609123321"

        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "number": phone,
                        "verified": False,
                        "primary": False,
                        "csrf_token": sess.get_csrf_token(),
                    }

                client.post("/new", data=json.dumps(data), content_type=self.content_type_json)

                with client.session_transaction() as sess:
                    sess.phone.captcha.completed = True
                    sess.persist()
                    data2: dict[str, Any] = {
                        "number": phone,
                        "csrf_token": sess.get_csrf_token(),
                    }

                client.post("/send-code", data=json.dumps(data2), content_type=self.content_type_json)

                with client.session_transaction() as sess:
                    data = {"number": phone, "code": "12345", "csrf_token": sess.get_csrf_token()}

        response2 = client.post("/verify", data=json.dumps(data), content_type=self.content_type_json)
        verify_phone_data = json.loads(response2.data)
        assert verify_phone_data["type"] == "POST_PHONE_VERIFY_SUCCESS"

        with self.app.test_request_context():
            with client.session_transaction() as sess:
                data = {"number": self.test_number, "csrf_token": sess.get_csrf_token()}

        response2 = client.post("/remove", data=json.dumps(data), content_type=self.content_type_json)

        assert response2.status_code == 200

        delete_phone_data = json.loads(response2.data)

        assert delete_phone_data["type"] == "POST_PHONE_REMOVE_SUCCESS"
        assert delete_phone_data["payload"]["phones"][0].get("number") == "+34 6096096096"

    def test_send_code(self) -> None:
        response = self.browser.post("/send-code")
        assert response.status_code == 401

        response = self._send_code()

        assert response.status_code == 200
        phone_data = json.loads(response.data)

        assert phone_data["type"] == "POST_PHONE_SEND_CODE_SUCCESS"
        assert self.test_number == phone_data["payload"]["phones"][0].get("number")
        assert phone_data["payload"]["phones"][1].get("number") == "+34 6096096096"

    def test_send_code_no_csrf(self) -> None:
        data = {"csrf_token": "wrong-token"}
        response = self._send_code(mod_data=data)

        assert response.status_code == 200
        phone_data = json.loads(response.data)

        assert phone_data["type"] == "POST_PHONE_SEND_CODE_FAIL"
        assert phone_data["payload"]["error"]["csrf_token"] == ["CSRF failed to validate"]

    def test_send_code_no_captcha(self) -> None:
        response = self._send_code(captcha_completed=False)

        assert response.status_code == 200
        phone_data = json.loads(response.data)

        assert phone_data["type"] == "POST_PHONE_SEND_CODE_FAIL"
        assert phone_data["payload"]["message"] == "phone.captcha-not-completed"

    def test_resend_code_throttle(self) -> None:
        response = self._send_code()

        assert response.status_code == 200
        phone_data = json.loads(response.data)

        assert phone_data["type"] == "POST_PHONE_SEND_CODE_SUCCESS"
        assert self.test_number == phone_data["payload"]["phones"][0].get("number")
        assert phone_data["payload"]["phones"][1].get("number") == "+34 6096096096"

        response = self._send_code()

        assert response.status_code == 200
        phone_data = json.loads(response.data)

        assert phone_data["type"] == "POST_PHONE_SEND_CODE_FAIL"
        assert phone_data["error"]
        assert phone_data["payload"]["message"] == "still-valid-code"
        assert phone_data["payload"]["csrf_token"] is not None

    def test_resend_code_with_expired_state(self) -> None:
        response = self._send_code()
        assert response.status_code == 200
        phone_data = json.loads(response.data)

        assert phone_data["type"] == "POST_PHONE_SEND_CODE_SUCCESS"
        assert self.test_number == phone_data["payload"]["phones"][0].get("number")
        assert phone_data["payload"]["phones"][1].get("number") == "+34 6096096096"

        # expire the just created state
        state = self.app.proofing_statedb.get_state_by_eppn_and_mobile(self.test_user.eppn, self.test_number)
        assert state
        assert state.modified_ts
        state.modified_ts = state.modified_ts - timedelta(seconds=self.app.conf.phone_verification_timeout)
        self.app.proofing_statedb._coll.replace_one({"_id": state.id}, state.to_dict())

        response = self._send_code()
        assert response.status_code == 200
        phone_data = json.loads(response.data)

        assert phone_data["type"] == "POST_PHONE_SEND_CODE_SUCCESS"
        assert self.test_number == phone_data["payload"]["phones"][0].get("number")
        assert phone_data["payload"]["phones"][1].get("number") == "+34 6096096096"

    def test_verify(self, mocker: MockerFixture) -> None:
        mock_request_user_sync = mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_code_verification = mocker.patch("eduid.webapp.phone.verifications.get_short_hash")
        mock_phone_validator = mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms")
        mock_phone_validator.return_value = True
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_code_verification.return_value = "12345"

        response = self.browser.post("/verify")
        assert response.status_code == 401

        eppn = self.test_user_data["eduPersonPrincipalName"]
        phone = "+34609123321"

        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "number": phone,
                        "verified": False,
                        "primary": False,
                        "csrf_token": sess.get_csrf_token(),
                    }

                client.post("/new", data=json.dumps(data), content_type=self.content_type_json)

                with client.session_transaction() as sess:
                    sess.phone.captcha.completed = True
                    sess.persist()
                    data2: dict[str, Any] = {
                        "number": phone,
                        "csrf_token": sess.get_csrf_token(),
                    }

                client.post("/send-code", data=json.dumps(data2), content_type=self.content_type_json)

                with client.session_transaction() as sess:
                    data3 = {"number": phone, "code": "12345", "csrf_token": sess.get_csrf_token()}

                response2 = client.post("/verify", data=json.dumps(data3), content_type=self.content_type_json)

            verify_phone_data = json.loads(response2.data)
            assert verify_phone_data["type"] == "POST_PHONE_VERIFY_SUCCESS"
            assert phone == verify_phone_data["payload"]["phones"][2]["number"]
            assert verify_phone_data["payload"]["phones"][2]["verified"]
            assert not verify_phone_data["payload"]["phones"][2]["primary"]
            assert self.app.proofing_log.db_count() == 1

    def test_verify_fail(self, mocker: MockerFixture) -> None:
        mock_request_user_sync = mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_code_verification = mocker.patch("eduid.webapp.phone.verifications.get_short_hash")
        mock_phone_validator = mocker.patch("eduid.common.rpc.msg_relay.MsgRelay.sendsms")
        mock_phone_validator.return_value = True
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_code_verification.return_value = "12345"

        response = self.browser.post("/verify")
        assert response.status_code == 401

        eppn = self.test_user_data["eduPersonPrincipalName"]
        phone = "+34609123321"

        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "number": phone,
                        "verified": False,
                        "primary": False,
                        "csrf_token": sess.get_csrf_token(),
                    }

                client.post("/new", data=json.dumps(data), content_type=self.content_type_json)

                with client.session_transaction() as sess:
                    sess.phone.captcha.completed = True
                    sess.persist()
                    data2: dict[str, Any] = {
                        "number": phone,
                        "csrf_token": sess.get_csrf_token(),
                    }

                client.post("/send-code", data=json.dumps(data2), content_type=self.content_type_json)

                with client.session_transaction() as sess:
                    data3 = {"number": phone, "code": "wrong_code", "csrf_token": sess.get_csrf_token()}

                response2 = client.post("/verify", data=json.dumps(data3), content_type=self.content_type_json)

                verify_phone_data = json.loads(response2.data)
                assert verify_phone_data["type"] == "POST_PHONE_VERIFY_FAIL"
                assert verify_phone_data["payload"]["message"] == "phones.code_invalid_or_expired"
                assert self.app.proofing_log.db_count() == 0

    def test_post_phone_duplicated_number(self) -> None:
        data = {"number": "0701234565"}
        response1 = self._post_phone(mod_data=data)

        assert response1.status_code == 200
        new_phone_data = json.loads(response1.data)

        assert new_phone_data["type"] == "POST_PHONE_NEW_SUCCESS"
        assert new_phone_data["payload"]["phones"][2].get("number") == "+46701234565"
        assert not new_phone_data["payload"]["phones"][2].get("verified")

        eppn = self.test_user_data["eduPersonPrincipalName"]

        # Save above phone number for user in central db
        user = self.app.private_userdb.get_user_by_eppn(eppn)
        self.request_user_sync(user)

        response2 = self._post_phone(mod_data=data)

        assert response2.status_code == 200

        new_phone_data2 = json.loads(response2.data)

        assert new_phone_data2["type"] == "POST_PHONE_NEW_FAIL"
        assert new_phone_data2["payload"]["error"].get("number") == ["phone.phone_duplicated"]

    def test_post_phone_duplicated_number_e_164(self) -> None:
        data = {"number": "+46701234565"}  # e164 format
        response1 = self._post_phone(mod_data=data)

        assert response1.status_code == 200
        new_phone_data = json.loads(response1.data)

        assert new_phone_data["type"] == "POST_PHONE_NEW_SUCCESS"
        assert new_phone_data["payload"]["phones"][2].get("number") == "+46701234565"
        assert not new_phone_data["payload"]["phones"][2].get("verified")

        eppn = self.test_user_data["eduPersonPrincipalName"]

        # Save above phone number for user in central db
        user = self.app.private_userdb.get_user_by_eppn(eppn)
        self.request_user_sync(user)

        data = {"number": "0701234565"}  # National format
        response2 = self._post_phone(mod_data=data)

        assert response2.status_code == 200

        new_phone_data2 = json.loads(response2.data)

        assert new_phone_data2["type"] == "POST_PHONE_NEW_FAIL"
        assert new_phone_data2["payload"]["error"].get("number") == ["phone.phone_duplicated"]

    def test_post_phone_duplicated_number_e_164_2(self) -> None:
        data = {"number": "0701234565"}  # e164 format
        response1 = self._post_phone(mod_data=data)

        assert response1.status_code == 200
        new_phone_data = json.loads(response1.data)

        assert new_phone_data["type"] == "POST_PHONE_NEW_SUCCESS"
        assert new_phone_data["payload"]["phones"][2].get("number") == "+46701234565"
        assert not new_phone_data["payload"]["phones"][2].get("verified")

        eppn = self.test_user_data["eduPersonPrincipalName"]

        # Save above phone number for user in central db
        user = self.app.private_userdb.get_user_by_eppn(eppn)
        self.request_user_sync(user)

        data = {"number": "+46701234565"}  # National format
        response2 = self._post_phone(mod_data=data)

        assert response2.status_code == 200

        new_phone_data2 = json.loads(response2.data)

        assert new_phone_data2["type"] == "POST_PHONE_NEW_FAIL"
        assert new_phone_data2["payload"]["error"].get("number") == ["phone.phone_duplicated"]

    def test_get_code_backdoor(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        code = "0123456"
        resp = self._get_code_backdoor(code=code)

        assert resp.status_code == 200
        assert resp.data == code.encode("ascii")

    def test_get_code_no_backdoor_in_pro(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("production")

        code = "0123456"
        resp = self._get_code_backdoor(code=code)

        assert resp.status_code == 400

    def test_get_code_no_backdoor_misconfigured1(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = ""
        self.app.conf.environment = EduidEnvironment("dev")

        code = "0123456"
        resp = self._get_code_backdoor(code=code, magic_cookie_name="wrong_name")

        assert resp.status_code == 400

    def test_get_code_no_backdoor_misconfigured2(self) -> None:
        self.app.conf.magic_cookie = ""
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        code = "0123456"
        resp = self._get_code_backdoor(code=code)

        assert resp.status_code == 400
