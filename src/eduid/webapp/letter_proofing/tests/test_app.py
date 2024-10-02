import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any, AnyStr
from unittest.mock import MagicMock, Mock, patch

from werkzeug.test import TestResponse

from eduid.common.config.base import EduidEnvironment
from eduid.userdb import NinIdentity
from eduid.userdb.element import ElementKey
from eduid.userdb.identity import IdentityType
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.letter_proofing.app import LetterProofingApp, init_letter_proofing_app
from eduid.webapp.letter_proofing.helpers import LetterMsg

__author__ = "lundberg"


class LetterProofingTests(EduidAPITestCase[LetterProofingApp]):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self) -> None:  # type: ignore[override]
        self.test_user_eppn = "hubba-baar"
        self.test_user_nin = "200001023456"
        self.test_user_wrong_nin = "190001021234"
        super().setUp(users=["hubba-baar"])

    @staticmethod
    def mock_response(
        status_code: int = 200,
        content: AnyStr | None = None,
        json_data: Mapping[str, Any] | None = None,
        headers: Mapping[str, Any] | None = None,
        raise_for_status: Any = None,
    ) -> Mock:
        """
        since we typically test a bunch of different
        requests calls for a service, we are going to do
        a lot of mock responses, so its usually a good idea
        to have a helper function that builds these things
        """
        if headers is None:
            headers = {}
        mock_resp = Mock()
        # mock raise_for_status call w/optional error
        mock_resp.raise_for_status = Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status
        # set status code and content
        mock_resp.status_code = status_code
        mock_resp.content = content
        # set headers
        mock_resp.headers = headers
        # add json data if provided
        if json_data:
            mock_resp.json = Mock(return_value=json_data)
        return mock_resp

    def load_app(self, config: dict[str, Any]) -> LetterProofingApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_letter_proofing_app("testing", config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                # 'ekopost_debug_pdf': devnull, # set to file path if debugging # noqa: ERA001
                "ekopost_api_uri": "http://localhost",
                "ekopost_api_user": "ekopost_user",
                "ekopost_api_pw": "secret",
                "letter_wait_time_hours": 336,
            }
        )
        return config

    # Helper methods
    def get_state(self) -> Any:
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            response = client.get("/proofing")
        self.assertEqual(response.status_code, 200)
        return json.loads(response.data)

    def send_letter(self, nin: str, csrf_token: str | None = None, validate_response: bool = True) -> TestResponse:
        """
        Invoke the POST /proofing endpoint, check that the HTTP response code is 200 and return the response.

        To be used with the data validation functions _check_success_response and _check_error_response.
        """
        response = self._send_letter2(nin, csrf_token)
        if validate_response:
            self._check_success_response(
                response, type_="POST_LETTER_PROOFING_PROOFING_SUCCESS", msg=LetterMsg.letter_sent
            )
        return response

    @patch("hammock.Hammock._request")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_postal_address")
    def _send_letter2(
        self,
        nin: str,
        csrf_token: str | None,
        mock_get_postal_address: MagicMock,
        mock_request_user_sync: MagicMock,
        mock_hammock: MagicMock,
    ):
        if csrf_token is None:
            _state = self.get_state()
            csrf_token = _state["payload"]["csrf_token"]

        ekopost_response = self.mock_response(json_data={"id": "test"})
        mock_hammock.return_value = ekopost_response
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_get_postal_address.return_value = self._get_full_postal_address()
        data = {"nin": nin, "csrf_token": csrf_token}
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            response = client.post("/proofing", data=json.dumps(data), content_type=self.content_type_json)
        return response

    def verify_code(self, code: str, csrf_token: str | None = None, validate_response: bool = True) -> TestResponse:
        """
        Invoke the POST /verify-code endpoint, check that the HTTP response code is 200 and return the response.

        To be used with the data validation functions _check_success_response and _check_error_response.
        """
        response = self._verify_code2(code, csrf_token)
        if validate_response:
            self._check_success_response(
                response, type_="POST_LETTER_PROOFING_VERIFY_CODE_SUCCESS", msg=LetterMsg.verify_success
            )
        return response

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_postal_address")
    def _verify_code2(
        self, code: str, csrf_token: str | None, mock_get_postal_address: MagicMock, mock_request_user_sync: MagicMock
    ):
        if csrf_token is None:
            _state = self.get_state()
            csrf_token = _state["payload"]["csrf_token"]

        mock_request_user_sync.side_effect = self.request_user_sync
        mock_get_postal_address.return_value = self._get_full_postal_address()
        data = {"code": code, "csrf_token": csrf_token}
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            response = client.post("/verify-code", data=json.dumps(data), content_type=self.content_type_json)
        return response

    @patch("hammock.Hammock._request")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_postal_address")
    def get_code_backdoor(
        self,
        mock_get_postal_address: Any,
        mock_request_user_sync: Any,
        mock_hammock: Any,
        cookie_name: str | None = None,
        cookie_value: str | None = None,
        add_cookie: bool = True,
    ) -> TestResponse:
        ekopost_response = self.mock_response(json_data={"id": "test"})
        mock_hammock.return_value = ekopost_response
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_get_postal_address.return_value = self._get_full_postal_address()

        nin = self.test_user_nin
        json_data = self.get_state()
        csrf_token = json_data["payload"]["csrf_token"]
        data = {"nin": nin, "csrf_token": csrf_token}

        if add_cookie is False:
            with self.session_cookie(self.browser, self.test_user_eppn) as client:
                response = client.post("/proofing", data=json.dumps(data), content_type=self.content_type_json)
                self.assertEqual(response.status_code, 200)
                return client.get("/get-code")

        with self.session_cookie_and_magic_cookie(
            self.browser, self.test_user_eppn, magic_cookie_name=cookie_name, magic_cookie_value=cookie_value
        ) as client:
            response = client.post("/proofing", data=json.dumps(data), content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)
            return client.get("/get-code")

    # End helper methods

    def test_authenticate(self) -> None:
        response = self.browser.get("/proofing")
        self.assertEqual(response.status_code, 401)
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            response = client.get("/proofing")
        self.assertEqual(response.status_code, 200)  # Authenticated request

    def test_letter_not_sent_status(self) -> None:
        json_data = self.get_state()
        assert json_data["payload"]["message"] == LetterMsg.no_state.value

    def test_send_letter(self) -> None:
        response = self.send_letter(self.test_user_nin)
        expires = self.get_response_payload(response)["letter_expires"]
        expires = datetime.fromisoformat(expires)
        self.assertIsInstance(expires, datetime)
        # Check that the user was given until midnight the day the code expires
        assert expires.hour == 23
        assert expires.minute == 59
        assert expires.second == 59

    def test_resend_letter(self) -> None:
        response = self.send_letter(self.test_user_nin)

        # Deliberately test the CSRF token from the send_letter response,
        # instead of always using get_state() to get a token.
        csrf_token = self.get_response_payload(response)["csrf_token"]
        response2 = self.send_letter(self.test_user_nin, csrf_token, validate_response=False)
        self._check_success_response(
            response2, type_="POST_LETTER_PROOFING_PROOFING_SUCCESS", msg=LetterMsg.already_sent
        )

        expires = self.get_response_payload(response2)["letter_expires"]
        expires = datetime.fromisoformat(expires)
        self.assertIsInstance(expires, datetime)
        expires = expires.strftime("%Y-%m-%d")
        self.assertIsInstance(expires, str)

    def test_send_letter_bad_csrf(self) -> None:
        response = self.send_letter(self.test_user_nin, "bad_csrf", validate_response=False)
        self._check_error_response(
            response, type_="POST_LETTER_PROOFING_PROOFING_FAIL", error={"csrf_token": ["CSRF failed to validate"]}
        )

    def test_letter_sent_status(self) -> None:
        self.send_letter(self.test_user_nin)
        json_data = self.get_state()
        self.assertIn("letter_sent", json_data["payload"])
        expires = datetime.fromisoformat(json_data["payload"]["letter_expires"])
        self.assertIsInstance(expires, datetime)
        expires_string = expires.strftime("%Y-%m-%d")
        self.assertIsInstance(expires_string, str)

    def test_verify_letter_code(self) -> None:
        response1 = self.send_letter(self.test_user_nin)
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        # Deliberately test the CSRF token from the send_letter response,
        # instead of always using get_state() to get a token.
        csrf_token = self.get_response_payload(response1)["csrf_token"]
        assert proofing_state is not None
        assert proofing_state.nin is not None
        assert proofing_state.nin.verification_code is not None
        response2 = self.verify_code(proofing_state.nin.verification_code, csrf_token)
        self._check_success_response(
            response2,
            type_="POST_LETTER_PROOFING_VERIFY_CODE_SUCCESS",
            payload={
                "identities": {
                    "is_verified": True,
                    "nin": {
                        "number": self.test_user_nin,
                        "verified": True,
                    },
                },
            },
        )

        # TODO: When LogElements have working from_dict/to_dict, implement a proofing_log.get_proofings_by_eppn()
        #       and work on the returned LetterProofing instance instead of with a mongo document
        log_docs = self.app.proofing_log._get_documents_by_attr("eduPersonPrincipalName", self.test_user_eppn)
        assert 1 == len(log_docs)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self._check_nin_verified_ok(user=user, proofing_state=proofing_state, number=self.test_user_nin)

    def test_verify_letter_code_bad_csrf(self) -> None:
        self.send_letter(self.test_user_nin)
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        assert proofing_state is not None
        assert proofing_state.nin is not None
        assert proofing_state.nin.verification_code is not None
        response = self.verify_code(proofing_state.nin.verification_code, "bad_csrf", validate_response=False)
        self._check_error_response(
            response, type_="POST_LETTER_PROOFING_VERIFY_CODE_FAIL", error={"csrf_token": ["CSRF failed to validate"]}
        )

    def test_verify_letter_code_fail(self) -> None:
        self.send_letter(self.test_user_nin)
        response = self.verify_code("wrong code", validate_response=False)
        self._check_error_response(response, type_="POST_LETTER_PROOFING_VERIFY_CODE_FAIL", msg=LetterMsg.wrong_code)

    def test_verify_letter_expired(self) -> None:
        response = self.send_letter(self.test_user_nin)
        # move the proofing state back in time so that it is expired by now
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        assert proofing_state is not None
        assert proofing_state.nin is not None
        assert proofing_state.nin.verification_code is not None
        proofing_state.proofing_letter.sent_ts = datetime.fromisoformat("2020-01-01T01:02:03")
        self.app.proofing_statedb.save(proofing_state)

        csrf_token = self.get_response_payload(response)["csrf_token"]
        response = self.verify_code(proofing_state.nin.verification_code, csrf_token, validate_response=False)
        self._check_error_response(
            response, type_="POST_LETTER_PROOFING_VERIFY_CODE_FAIL", msg=LetterMsg.letter_expired
        )

    def test_proofing_flow(self) -> None:
        self.send_letter(self.test_user_nin)
        self.get_state()
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        assert proofing_state is not None
        assert proofing_state.nin is not None
        assert proofing_state.nin.verification_code is not None
        self.verify_code(proofing_state.nin.verification_code, None)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self._check_nin_verified_ok(user=user, proofing_state=proofing_state, number=self.test_user_nin)

    def test_proofing_flow_previously_added_nin(self) -> None:
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        not_verified_nin = NinIdentity(number=self.test_user_nin, created_by="test", is_verified=False)
        user.identities.add(not_verified_nin)
        self.app.central_userdb.save(user)

        self.send_letter(self.test_user_nin)
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(user.eppn)
        assert proofing_state is not None
        assert proofing_state.nin is not None
        assert proofing_state.nin.verification_code is not None
        self.verify_code(proofing_state.nin.verification_code, None)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self._check_nin_verified_ok(
            user=user, proofing_state=proofing_state, number=self.test_user_nin, created_by=not_verified_nin.created_by
        )

    def test_proofing_flow_previously_added_wrong_nin(self) -> None:
        # Send letter to correct nin
        self.send_letter(self.test_user_nin)

        # Remove correct unverified nin and add wrong nin
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        user.identities.remove(ElementKey(IdentityType.NIN))
        not_verified_nin = NinIdentity(number=self.test_user_wrong_nin, created_by="test", is_verified=False)
        user.identities.add(not_verified_nin)
        self.app.central_userdb.save(user)

        # Time passes, user gets code in the mail. Enters code.
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(user.eppn)
        assert proofing_state is not None
        assert proofing_state.nin is not None
        assert proofing_state.nin.verification_code is not None
        self.verify_code(proofing_state.nin.verification_code, None)

        # Now check that the (now verified) NIN on the user is back to the one used to request the letter
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self._check_nin_verified_ok(user=user, proofing_state=proofing_state, number=self.test_user_nin)

    def test_expire_proofing_state(self) -> None:
        self.send_letter(self.test_user_nin)
        json_data = self.get_state()
        self.assertIn("letter_sent", json_data["payload"])
        self.app.conf.letter_wait_time_hours = -24
        json_data = self.get_state()
        self.assertTrue(json_data["payload"]["letter_expired"])
        self.assertIn("letter_sent", json_data["payload"])
        self.assertIsNotNone(json_data["payload"]["letter_sent"])

    def test_send_new_letter_with_expired_proofing_state(self) -> None:
        self.send_letter(self.test_user_nin)
        json_data = self.get_state()
        self.assertIn("letter_sent", json_data["payload"])
        self.app.conf.letter_wait_time_hours = -24
        self.send_letter(self.test_user_nin)
        self.assertFalse(json_data["payload"]["letter_expired"])
        self.assertIn("letter_sent", json_data["payload"])
        self.assertIsNotNone(json_data["payload"]["letter_sent"])

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_postal_address")
    def test_unmarshal_error(self, mock_get_postal_address: MagicMock) -> None:
        mock_get_postal_address.return_value = self._get_full_postal_address()

        response = self.send_letter("not a nin", validate_response=False)

        self._check_error_response(
            response,
            type_="POST_LETTER_PROOFING_PROOFING_FAIL",
            error={"nin": ["nin needs to be formatted as 18|19|20yymmddxxxx"]},
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_postal_address")
    def test_locked_identity_no_locked_identity(
        self, mock_get_postal_address: MagicMock, mock_request_user_sync: MagicMock
    ) -> None:
        mock_get_postal_address.return_value = self._get_full_postal_address()
        mock_request_user_sync.side_effect = self.request_user_sync
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.locked_identity.count, 0)

        # User with no locked_identity
        with self.session_cookie(self.browser, self.test_user_eppn):
            self.send_letter(self.test_user_nin)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_postal_address")
    def test_locked_identity_correct_nin(
        self, mock_get_postal_address: MagicMock, mock_request_user_sync: MagicMock
    ) -> None:
        mock_get_postal_address.return_value = self._get_full_postal_address()
        mock_request_user_sync.side_effect = self.request_user_sync
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        # User with locked_identity and correct nin
        user.locked_identity.add(NinIdentity(number=self.test_user_nin, created_by="test", is_verified=True))
        self.app.central_userdb.save(user)
        with self.session_cookie(self.browser, self.test_user_eppn):
            self.send_letter(self.test_user_nin)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_postal_address")
    def test_locked_identity_incorrect_nin(
        self, mock_get_postal_address: MagicMock, mock_request_user_sync: MagicMock
    ) -> None:
        mock_get_postal_address.return_value = self._get_full_postal_address()
        mock_request_user_sync.side_effect = self.request_user_sync
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        user.locked_identity.add(NinIdentity(number=self.test_user_nin, created_by="test", is_verified=True))
        self.app.central_userdb.save(user)

        # User with locked_identity and incorrect nin
        with self.session_cookie(self.browser, self.test_user_eppn):
            response = self.send_letter("200102031234", validate_response=False)
        self._check_error_response(
            response,
            type_="POST_LETTER_PROOFING_PROOFING_FAIL",
            payload={"message": "Another nin is already registered for this user"},
        )

    @patch("hammock.Hammock._request")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_send_letter_backdoor(self, mock_request_user_sync: MagicMock, mock_hammock: MagicMock) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        ekopost_response = self.mock_response(json_data={"id": "test"})
        mock_hammock.return_value = ekopost_response
        mock_request_user_sync.side_effect = self.request_user_sync

        _state = self.get_state()
        csrf_token = _state["payload"]["csrf_token"]
        data = {"nin": self.test_user_nin, "csrf_token": csrf_token}
        with self.session_cookie_and_magic_cookie(self.browser, eppn=self.test_user_eppn) as client:
            response = client.post("/proofing", data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_="POST_LETTER_PROOFING_PROOFING_SUCCESS", msg=LetterMsg.letter_sent)

    def test_get_code_backdoor(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        response = self.get_code_backdoor()
        state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        assert state is not None
        self.assertEqual(response.data.decode("ascii"), state.nin.verification_code)

    def test_get_code_no_backdoor_in_pro(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("production")

        response = self.get_code_backdoor()

        self.assertEqual(response.status_code, 400)

    def test_get_code_no_backdoor_without_cookie(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        response = self.get_code_backdoor(add_cookie=False)

        self.assertEqual(response.status_code, 400)

    def test_get_code_no_backdoor_misconfigured1(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = ""
        self.app.conf.environment = EduidEnvironment("dev")

        response = self.get_code_backdoor(cookie_name="wrong_name")

        self.assertEqual(response.status_code, 400)

    def test_get_code_no_backdoor_misconfigured2(self) -> None:
        self.app.conf.magic_cookie = ""
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        response = self.get_code_backdoor()

        self.assertEqual(response.status_code, 400)

    def test_get_code_no_backdoor_wrong_value(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        response = self.get_code_backdoor(cookie_value="wrong-cookie")

        self.assertEqual(response.status_code, 400)

    def test_state_days_info(self) -> None:
        """Validate calculation of days information in state retrieval"""
        self.send_letter(self.test_user_nin)
        json_data = self.get_state()

        assert json_data["payload"]["letter_sent_days_ago"] == 0
        assert json_data["payload"]["letter_expires_in_days"] == 14
        assert json_data["payload"]["letter_expired"] is False
        assert json_data["payload"]["message"] == LetterMsg.already_sent.value

        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        assert proofing_state is not None
        assert proofing_state.proofing_letter is not None
        assert proofing_state.proofing_letter.sent_ts is not None

        # move back the 'letter sent' value to the last second of yesterday
        new_ts = proofing_state.proofing_letter.sent_ts - timedelta(days=1)
        new_ts = new_ts.replace(hour=23, minute=59, second=59)
        proofing_state.proofing_letter.sent_ts = new_ts
        self.app.proofing_statedb.save(proofing_state)

        json_data = self.get_state()

        assert json_data["payload"]["letter_sent_days_ago"] == 1
        assert json_data["payload"]["letter_expires_in_days"] == 13
        assert json_data["payload"]["letter_expired"] is False
        assert json_data["payload"]["message"] == LetterMsg.already_sent.value

        # move back the 'letter sent' value to the last day of validity
        new_ts = proofing_state.proofing_letter.sent_ts - timedelta(days=13)
        new_ts = new_ts.replace(hour=23, minute=59, second=59)
        proofing_state.proofing_letter.sent_ts = new_ts
        self.app.proofing_statedb.save(proofing_state)

        json_data = self.get_state()

        assert json_data["payload"]["letter_sent_days_ago"] == 14
        assert json_data["payload"]["letter_expires_in_days"] == 0
        assert json_data["payload"]["letter_expired"] is False
        assert json_data["payload"]["message"] == LetterMsg.already_sent.value

        # make the state expired
        new_ts = proofing_state.proofing_letter.sent_ts - timedelta(days=1)
        new_ts = new_ts.replace(hour=23, minute=59, second=59)
        proofing_state.proofing_letter.sent_ts = new_ts
        self.app.proofing_statedb.save(proofing_state)

        json_data = self.get_state()

        assert json_data["payload"]["letter_sent_days_ago"] == 15
        assert "letter_expires_in_days" not in json_data["payload"]
        assert json_data["payload"]["letter_expired"] is True
        assert json_data["payload"]["message"] == LetterMsg.letter_expired.value

    def test_proofing_with_a_verified_nin(self) -> None:
        """Test that no letter is sent when the user already has a verified NIN"""
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        verified_nin = NinIdentity(number=self.test_user_nin, created_by="test", is_verified=True, verified_by="test")
        user.identities.add(verified_nin)
        self.app.central_userdb.save(user)

        response = self.send_letter(self.test_user_nin, validate_response=False)
        self._check_error_response(
            response,
            type_="POST_LETTER_PROOFING_PROOFING_FAIL",
            payload={"message": "User is already verified"},
        )

        proofing_state = self.app.proofing_statedb.get_state_by_eppn(user.eppn)
        assert proofing_state is None
