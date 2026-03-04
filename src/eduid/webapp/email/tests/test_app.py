import json
from collections.abc import Mapping
from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock, patch

from werkzeug.test import TestResponse

from eduid.common.config.base import EduidEnvironment
from eduid.common.misc.timeutil import utc_now
from eduid.userdb import User
from eduid.userdb.mail import MailAddress
from eduid.userdb.proofing import EmailProofingElement, EmailProofingState
from eduid.userdb.testing import SetupConfig
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.email.app import EmailApp, email_init_app


class EmailTests(EduidAPITestCase[EmailApp]):
    def setUp(self, config: SetupConfig | None = None) -> None:
        if config is None:
            config = SetupConfig()
        config.copy_user_to_private = True
        super().setUp(config=config)

    def load_app(self, config: Mapping[str, Any]) -> EmailApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return email_init_app("emails", config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                "available_languages": {"en": "English", "sv": "Svenska"},
                "email_verify_redirect_url": "/profile/",
                "email_verification_timeout": 86400,
                "throttle_resend_seconds": 300,
                "eduid_site_url": "https://eduid.dev/",
            }
        )
        return config

    def _remove_all_emails(self, user: User) -> None:
        unverified = [address for address in user.mail_addresses.to_list() if not address.is_verified]
        verified = [address for address in user.mail_addresses.to_list() if address.is_verified]
        for address in unverified:
            user.mail_addresses.remove(address.key)
        for address in verified:
            user.mail_addresses.remove(address.key)

    def _add_2_emails(self, user: User) -> None:
        verified = MailAddress(email="verified@example.com", created_by="test", is_verified=True, is_primary=True)
        verified2 = MailAddress(email="verified2@example.com", created_by="test", is_verified=True, is_primary=False)
        user.mail_addresses.add(verified)
        user.mail_addresses.add(verified2)

    def _add_2_emails_1_verified(self, user: User) -> None:
        verified = MailAddress(email="verified@example.com", created_by="test", is_verified=True, is_primary=True)
        verified2 = MailAddress(email="unverified@example.com", created_by="test", is_verified=False, is_primary=False)
        user.mail_addresses.add(verified)
        user.mail_addresses.add(verified2)

    # Parameterized test methods

    def _get_all_emails(self) -> dict:
        """
        GET a list with all the email addresses of the test user
        """
        response = self.browser.get("/all")
        self.assertEqual(response.status_code, 401)

        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get("/all")

            return json.loads(response2.data)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.webapp.email.verifications.get_short_hash")
    def _post_email(
        self,
        mock_code_verification: MagicMock,
        mock_request_user_sync: MagicMock,
        data1: dict[str, Any] | None = None,
        send_data: bool = True,
    ) -> TestResponse:
        """
        POST email data to add new email address to the test user.

        :param data1: to override the data POSTed by default
        :param send_data: whether to actually send data in the POST
        """
        response = self.browser.post("/new")
        self.assertEqual(response.status_code, 401)

        mock_code_verification.return_value = "123456"
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data["eduPersonPrincipalName"]

        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "email": "johnsmith3@example.com",
                        "verified": False,
                        "primary": False,
                        "csrf_token": sess.get_csrf_token(),
                    }
                if data1 is not None:
                    data.update(data1)

                if send_data:
                    return client.post("/new", data=json.dumps(data), content_type=self.content_type_json)

                return client.post("/new")

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _post_primary(self, mock_request_user_sync: MagicMock, data1: dict[str, Any] | None = None) -> TestResponse:
        """
        Choose an email of the test user as primary

        :param data: to control what is sent to the server in the POST
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self.browser.post("/primary")
        self.assertEqual(response.status_code, 401)

        eppn = self.test_user_data["eduPersonPrincipalName"]

        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "csrf_token": sess.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)

                return client.post("/primary", data=json.dumps(data), content_type=self.content_type_json)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _remove(self, mock_request_user_sync: MagicMock, data1: dict[str, Any] | None = None) -> TestResponse:
        """
        POST to remove an email address form the test user

        :param data: to control what data is POSTed to the service
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self.browser.post("/remove")
        self.assertEqual(response.status_code, 401)

        eppn = self.test_user_data["eduPersonPrincipalName"]

        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"csrf_token": sess.get_csrf_token()}
                if data1 is not None:
                    data.update(data1)

            return client.post("/remove", data=json.dumps(data), content_type=self.content_type_json)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _resend_code(self, mock_request_user_sync: MagicMock, data1: dict[str, Any] | None = None) -> TestResponse:
        """
        Trigger resending a new verification code to the email being verified

        :param data: to control what data is POSTed to the service
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data["eduPersonPrincipalName"]

        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"csrf_token": sess.get_csrf_token()}
                if data1 is not None:
                    data.update(data1)

            return client.post("/resend-code", data=json.dumps(data), content_type=self.content_type_json)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.webapp.email.verifications.get_short_hash")
    def _verify(
        self,
        mock_code_verification: MagicMock,
        mock_request_user_sync: MagicMock,
        data1: dict[str, Any] | None = None,
        data2: dict[str, Any] | None = None,
    ) -> TestResponse:
        """
        POST a new email address for the test user, and then verify it.

        :param data1: to control what data is POSTed to the /new endpoint
        :param data2: to control what data is POSTed to the /verify endpoint
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_code_verification.return_value = "432123425"

        response = self.browser.post("/verify")
        self.assertEqual(response.status_code, 401)

        eppn = self.test_user_data["eduPersonPrincipalName"]

        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "email": "john-smith3@example.com",
                        "verified": False,
                        "primary": False,
                        "csrf_token": sess.get_csrf_token(),
                    }
                if data1 is not None:
                    data.update(data1)

            client.post("/new", data=json.dumps(data), content_type=self.content_type_json)

            with client.session_transaction() as sess:
                data = {
                    "csrf_token": sess.get_csrf_token(),
                    "email": "john-smith3@example.com",
                    "code": "432123425",
                }
                if data2 is not None:
                    data.update(data2)

            return client.post("/verify", data=json.dumps(data), content_type=self.content_type_json)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.webapp.email.verifications.get_short_hash")
    def _get_code_backdoor(
        self,
        mock_code_verification: MagicMock,
        mock_request_user_sync: MagicMock,
        data1: dict[str, Any] | None = None,
        email: str = "johnsmith3@example.com",
        code: str = "123456",
        magic_cookie_name: str | None = None,
    ) -> TestResponse:
        """
        POST email data to generate a verification state,
        and try to get the generated code through the backdoor

        :param data1: to override the data POSTed by default
        :param email: email to use
        :param code: mock generated code
        """
        mock_code_verification.return_value = code
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data["eduPersonPrincipalName"]

        with self.session_cookie_and_magic_cookie(
            self.browser, eppn=eppn, magic_cookie_name=magic_cookie_name
        ) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "email": email,
                        "verified": False,
                        "primary": False,
                        "csrf_token": sess.get_csrf_token(),
                    }
                if data1 is not None:
                    data.update(data1)

            client.post("/new", data=json.dumps(data), content_type=self.content_type_json)
            return client.get(f"/get-code?email={email}&eppn={eppn}")

    # actual test methods

    def test_get_all_emails(self) -> None:
        email_data = self._get_all_emails()

        self.assertEqual(email_data["type"], "GET_EMAIL_ALL_SUCCESS")
        self.assertEqual(email_data["payload"]["emails"][0].get("email"), "johnsmith@example.com")
        self.assertEqual(email_data["payload"]["emails"][0].get("verified"), True)
        self.assertEqual(email_data["payload"]["emails"][1].get("email"), "johnsmith2@example.com")
        self.assertEqual(email_data["payload"]["emails"][1].get("verified"), False)

    def test_post_email(self) -> None:
        response = self._post_email()

        self.assertEqual(response.status_code, 200)
        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data["type"], "POST_EMAIL_NEW_SUCCESS")
        self.assertEqual(new_email_data["payload"]["emails"][2].get("email"), "johnsmith3@example.com")
        self.assertEqual(new_email_data["payload"]["emails"][2].get("verified"), False)

    def test_post_email_try_verify(self) -> None:
        data1 = {"verified": True}
        response = self._post_email(data1=data1)

        self.assertEqual(response.status_code, 200)
        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data["type"], "POST_EMAIL_NEW_SUCCESS")
        self.assertEqual(new_email_data["payload"]["emails"][2].get("email"), "johnsmith3@example.com")
        self.assertEqual(new_email_data["payload"]["emails"][2].get("verified"), False)

    def test_post_email_try_primary(self) -> None:
        data1 = {"verified": True, "primary": True}
        response = self._post_email(data1=data1)

        self.assertEqual(response.status_code, 200)
        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data["type"], "POST_EMAIL_NEW_SUCCESS")
        self.assertEqual(new_email_data["payload"]["emails"][2].get("email"), "johnsmith3@example.com")
        self.assertEqual(new_email_data["payload"]["emails"][2].get("verified"), False)
        self.assertEqual(new_email_data["payload"]["emails"][2].get("primary"), False)

    def test_post_email_with_stale_state(self) -> None:
        # set negative throttling timeout to simulate a stale state
        self.app.conf.throttle_resend_seconds = -500
        eppn = self.test_user_data["eduPersonPrincipalName"]
        email = "johnsmith3@example.com"
        verification1 = EmailProofingElement(email=email, verification_code="test_code_1")
        modified_ts = utc_now()
        old_state = EmailProofingState(id=None, eppn=eppn, modified_ts=modified_ts, verification=verification1)
        self.app.proofing_statedb.save(old_state, is_in_database=False)

        response = self._post_email()
        self.assertEqual(response.status_code, 200)
        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data["type"], "POST_EMAIL_NEW_SUCCESS")
        self.assertEqual(new_email_data["payload"]["emails"][2].get("email"), email)
        self.assertEqual(new_email_data["payload"]["emails"][2].get("verified"), False)

    def test_post_email_throttle(self) -> None:
        eppn = self.test_user_data["eduPersonPrincipalName"]
        email = "johnsmith3@example.com"
        modified_ts = utc_now()
        verification1 = EmailProofingElement(email=email, verification_code="test_code_1")
        old_state = EmailProofingState(id=None, eppn=eppn, modified_ts=modified_ts, verification=verification1)
        self.app.proofing_statedb.save(old_state, is_in_database=False)

        response = self._post_email()
        self.assertEqual(response.status_code, 200)
        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data["type"], "POST_EMAIL_NEW_SUCCESS")
        self.assertEqual(new_email_data["payload"]["message"], "emails.added-and-throttled")

    def test_post_email_error_no_data(self) -> None:
        response = self._post_email(send_data=False)

        new_email_data = json.loads(response.data)
        self.assertEqual(new_email_data["type"], "POST_EMAIL_NEW_FAIL")

    def test_post_email_duplicate(self) -> None:
        eppn = self.test_user_data["eduPersonPrincipalName"]
        email = "johnsmith3@example.com"

        # Save unverified mail address for test user
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        mail_address = MailAddress(email=email, created_by="email", is_verified=False, is_primary=False)
        user.mail_addresses.add(mail_address)
        self.app.central_userdb.save(user)

        response = self._post_email()
        self.assertEqual(response.status_code, 200)
        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data["type"], "POST_EMAIL_NEW_FAIL")
        self.assertEqual(new_email_data["payload"]["error"]["email"][0], "emails.duplicated")

    def test_post_email_bad_csrf(self) -> None:
        response = self._post_email(data1={"csrf_token": "bad-token"})

        self.assertEqual(response.status_code, 200)

        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data["type"], "POST_EMAIL_NEW_FAIL")
        self.assertEqual(new_email_data["payload"]["error"]["csrf_token"], ["CSRF failed to validate"])

    def test_post_primary(self) -> None:
        data1 = {"email": "johnsmith@example.com"}
        response = self._post_primary(data1=data1)

        self.assertEqual(response.status_code, 200)

        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data["type"], "POST_EMAIL_PRIMARY_SUCCESS")

    def test_post_unknown_primary(self) -> None:
        data1 = {"email": "susansmith@example.com"}
        response = self._post_primary(data1=data1)

        self.assertEqual(response.status_code, 200)

        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data["type"], "POST_EMAIL_PRIMARY_FAIL")

    def test_post_primary_missing(self) -> None:
        data1 = {"email": "johnsmith3@example.com"}
        response = self._post_primary(data1=data1)

        self.assertEqual(response.status_code, 200)

        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data["type"], "POST_EMAIL_PRIMARY_FAIL")
        self.assertEqual(new_email_data["payload"]["error"]["email"][0], "emails.missing")

    def test_post_primary_unconfirmed_fail(self) -> None:
        data1 = {"email": "johnsmith2@example.com"}
        response = self._post_primary(data1=data1)

        self.assertEqual(response.status_code, 200)

        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data["type"], "POST_EMAIL_PRIMARY_FAIL")
        self.assertEqual(new_email_data["payload"]["message"], "emails.unconfirmed_address_not_primary")

    def test_remove(self) -> None:
        data1 = {"email": "johnsmith2@example.com"}
        response = self._remove(data1=data1)

        self.assertEqual(response.status_code, 200)

        delete_email_data = json.loads(response.data)

        self.assertEqual(delete_email_data["type"], "POST_EMAIL_REMOVE_SUCCESS")
        self.assertEqual(delete_email_data["payload"]["emails"][0].get("email"), "johnsmith@example.com")

    def test_remove_primary(self) -> None:
        eppn = self.test_user_data["eduPersonPrincipalName"]
        user = self.app.central_userdb.get_user_by_eppn(eppn)

        # Remove all mail addresses to start with a known state
        self._remove_all_emails(user)

        # Add one verified, primary address and one not verified
        self._add_2_emails(user)

        self.request_user_sync(user)

        data1 = {"email": "verified@example.com"}
        response = self._remove(data1=data1)

        self.assertEqual(response.status_code, 200)
        delete_email_data = json.loads(response.data)
        self.assertEqual(delete_email_data["type"], "POST_EMAIL_REMOVE_SUCCESS")
        self.assertEqual(delete_email_data["payload"]["emails"][0].get("email"), "verified2@example.com")

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user.mail_addresses.primary is not None

        self.assertEqual(user.mail_addresses.count, 1)
        self.assertEqual(len(user.mail_addresses.verified), 1)
        self.assertEqual(user.mail_addresses.primary.email, "verified2@example.com")

    def test_remove_last_verified(self) -> None:
        eppn = self.test_user_data["eduPersonPrincipalName"]
        user = self.app.central_userdb.get_user_by_eppn(eppn)

        # Remove all mail addresses to start with a known state
        self._remove_all_emails(user)

        # Add one verified, primary address and one not verified
        self._add_2_emails_1_verified(user)

        self.request_user_sync(user)

        data1 = {"email": "verified@example.com"}
        response = self._remove(data1=data1)

        self.assertEqual(response.status_code, 200)
        delete_email_data = json.loads(response.data)
        self.assertEqual(delete_email_data["type"], "POST_EMAIL_REMOVE_FAIL")

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user.mail_addresses.primary is not None

        self.assertEqual(user.mail_addresses.count, 2)
        self.assertEqual(len(user.mail_addresses.verified), 1)
        self.assertEqual(user.mail_addresses.primary.email, "verified@example.com")

    def test_remove_fail(self) -> None:
        data1 = {"email": "johnsmith3@example.com"}
        response = self._remove(data1=data1)

        self.assertEqual(response.status_code, 200)
        delete_email_data = json.loads(response.data)

        self.assertEqual(delete_email_data["type"], "POST_EMAIL_REMOVE_FAIL")
        self.assertEqual(delete_email_data["payload"]["error"]["email"][0], "emails.missing")

    def test_resend_code(self) -> None:
        response = self.browser.post("/resend-code")
        self.assertEqual(response.status_code, 401)

        data1 = {"email": "johnsmith@example.com"}
        response = self._resend_code(data1=data1)

        self.assertEqual(response.status_code, 200)
        resend_code_email_data = json.loads(response.data)

        self.assertEqual(resend_code_email_data["type"], "POST_EMAIL_RESEND_CODE_SUCCESS")
        self.assertEqual(resend_code_email_data["payload"]["emails"][0].get("email"), "johnsmith@example.com")
        self.assertEqual(resend_code_email_data["payload"]["emails"][1].get("email"), "johnsmith2@example.com")

    def test_throttle_resend_code(self) -> None:
        data1 = {"email": "johnsmith@example.com"}
        response = self._resend_code(data1=data1)

        self.assertEqual(response.status_code, 200)

        response2 = self._resend_code(data1=data1)

        self.assertEqual(response2.status_code, 200)

        resend_code_email_data = json.loads(response2.data)

        self.assertEqual(resend_code_email_data["type"], "POST_EMAIL_RESEND_CODE_FAIL")
        self.assertEqual(resend_code_email_data["error"], True)
        self.assertEqual(resend_code_email_data["payload"]["message"], "still-valid-code")
        self.assertIsNotNone(resend_code_email_data["payload"]["csrf_token"])

    def test_resend_code_fails(self) -> None:
        data1 = {"email": "johnsmith3@example.com"}
        response = self._resend_code(data1=data1)

        self.assertEqual(response.status_code, 200)
        resend_code_email_data = json.loads(response.data)

        self.assertEqual(resend_code_email_data["type"], "POST_EMAIL_RESEND_CODE_FAIL")

        self.assertEqual(resend_code_email_data["payload"]["error"]["email"][0], "emails.missing")

    def test_verify(self) -> None:
        email = "john-smith3@example.com"
        response = self._verify()

        verify_email_data = json.loads(response.data)
        self.assertEqual(verify_email_data["type"], "POST_EMAIL_VERIFY_SUCCESS")
        self.assertEqual(verify_email_data["payload"]["emails"][2]["email"], email)
        self.assertEqual(verify_email_data["payload"]["emails"][2]["verified"], True)
        self.assertEqual(verify_email_data["payload"]["emails"][2]["primary"], False)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

        eppn = self.test_user_data["eduPersonPrincipalName"]
        user = self.app.private_userdb.get_user_by_eppn(eppn)
        mail_address_element = user.mail_addresses.find(email)
        assert mail_address_element is not None

        assert mail_address_element.email == email
        assert mail_address_element.is_verified
        assert not mail_address_element.is_primary
        assert self.app.proofing_log.db_count() == 1

    def test_verify_unknown(self) -> None:
        data2 = {"email": "susan@example.com"}
        response = self._verify(data2=data2)

        verify_email_data = json.loads(response.data)
        self.assertEqual(verify_email_data["type"], "POST_EMAIL_VERIFY_FAIL")

    def test_verify_no_primary(self) -> None:
        # Remove all mail addresses to start with no primary address
        eppn = self.test_user_data["eduPersonPrincipalName"]
        user = self.app.private_userdb.get_user_by_eppn(eppn)
        self._remove_all_emails(user)
        self.request_user_sync(user)

        response = self._verify()

        verify_email_data = json.loads(response.data)
        self.assertEqual(verify_email_data["type"], "POST_EMAIL_VERIFY_SUCCESS")
        self.assertEqual(len(verify_email_data["payload"]["emails"]), 1)
        self.assertEqual(verify_email_data["payload"]["emails"][0]["email"], "john-smith3@example.com")
        self.assertEqual(verify_email_data["payload"]["emails"][0]["verified"], True)
        self.assertEqual(verify_email_data["payload"]["emails"][0]["primary"], True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    def test_verify_code_timeout(self) -> None:
        self.app.conf.email_verification_timeout = timedelta(0)
        response = self._verify()

        verify_email_data = json.loads(response.data)
        self.assertEqual(verify_email_data["type"], "POST_EMAIL_VERIFY_FAIL")
        self.assertEqual(verify_email_data["payload"]["message"], "emails.code_invalid_or_expired")

    def test_verify_fail(self) -> None:
        response = self._verify(data2={"code": "wrong-code"})

        verify_email_data = json.loads(response.data)
        self.assertEqual(verify_email_data["type"], "POST_EMAIL_VERIFY_FAIL")
        self.assertEqual(verify_email_data["payload"]["message"], "emails.code_invalid_or_expired")
        self.assertEqual(self.app.proofing_log.db_count(), 0)

    def test_verify_email_uppercase(self) -> None:
        email = "JOHN-SMITH3@EXAMPLE.COM"
        response = self._verify(data1={"email": email})
        eppn = self.test_user_data["eduPersonPrincipalName"]

        self.assertEqual(response.status_code, 200)

        user = self.app.private_userdb.get_user_by_eppn(eppn)
        mail_address_element = user.mail_addresses.find(email.lower())
        assert mail_address_element is not None

        assert mail_address_element.email, email.lower()
        assert mail_address_element.is_verified
        assert not mail_address_element.is_primary
        assert self.app.proofing_log.db_count() == 1

    def test_handle_multiple_email_proofings(self) -> None:
        eppn = self.test_user_data["eduPersonPrincipalName"]
        email = "example@example.com"
        verification1 = EmailProofingElement(email=email, verification_code="test_code_1")
        verification2 = EmailProofingElement(email=email, verification_code="test_code_2")
        modified_ts = utc_now() - timedelta(seconds=1)
        state1 = EmailProofingState(id=None, eppn=eppn, modified_ts=modified_ts, verification=verification1)
        state2 = EmailProofingState(id=None, eppn=eppn, modified_ts=None, verification=verification2)
        self.app.proofing_statedb.save(state1, is_in_database=False)
        self.app.proofing_statedb.save(state2, is_in_database=False)
        state = self.app.proofing_statedb.get_state_by_eppn_and_email(eppn=eppn, email=email)
        assert state is not None
        self.assertEqual(state.verification.verification_code, "test_code_2")

    def test_get_code_backdoor(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        code = "0123456"
        resp = self._get_code_backdoor(code=code)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data, code.encode("ascii"))

    def test_get_code_no_backdoor_in_pro(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("production")

        code = "0123456"
        resp = self._get_code_backdoor(code=code)

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured1(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = ""
        self.app.conf.environment = EduidEnvironment("dev")

        code = "0123456"
        resp = self._get_code_backdoor(code=code, magic_cookie_name="wrong_name")

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured2(self) -> None:
        self.app.conf.magic_cookie = ""
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        code = "0123456"
        resp = self._get_code_backdoor(code=code)

        self.assertEqual(resp.status_code, 400)
