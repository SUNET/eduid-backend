import json
from datetime import datetime, timedelta
from typing import Any, Mapping, Optional
from unittest.mock import MagicMock, patch

from eduid.common.config.base import FrontendAction
from eduid.common.rpc.msg_relay import DeregisteredCauseCode, DeregistrationInformation, OfficialAddress
from eduid.userdb import User
from eduid.userdb.element import ElementKey
from eduid.userdb.identity import IdentityType
from eduid.webapp.common.api.schemas.authn_status import AuthnActionStatus
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.security.app import SecurityApp, security_init_app
from eduid.webapp.security.helpers import SecurityMsg


class SecurityTests(EduidAPITestCase[SecurityApp]):
    def setUp(self, *args: Any, **kwargs: Any):
        super().setUp(*args, **kwargs)

        self.test_user_eppn = "hubba-bubba"
        self.test_user_nin = "197801011235"

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
                "password_length": 12,
                "password_entropy": 25,
                "chpass_reauthn_timeout": 600,
                "eduid_site_name": "eduID",
                "eduid_site_url": "https://www.eduid.se/",
                "fido2_rp_id": "https://test.example.edu",
                "vccs_url": "https://vccs",
                "dashboard_url": "https://dashboard/",
                "logout_endpoint": "https://test.localhost/services/authn/logout",
            }
        )
        return config

    # parameterized test methods

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    @patch("eduid.webapp.security.views.security.revoke_all_credentials")
    def _delete_account(
        self,
        mock_revoke: Any,
        mock_sync: Any,
        data1: Optional[dict[str, Any]] = None,
    ):
        """
        Send a GET request to the endpoint to actually terminate the account,
        mocking re-authentication by setting a timestamp in the session.

        """
        mock_revoke.return_value = True
        mock_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            with client.session_transaction() as sess:
                data = {
                    "csrf_token": sess.get_csrf_token(),
                }
                if data1 is not None:
                    data.update(data1)

            return client.post("/terminate-account", json=data)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _remove_nin(self, mock_request_user_sync: Any, data1: Optional[dict[str, Any]] = None, unverify: bool = False):
        """
        Send a POST request to remove a NIN from the test user, possibly
        unverifying his verified NIN.

        :param data1: to control the data that is POSTed
        :param unverify: whether to unverify the test user NIN.
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True

        if unverify:
            user.identities.nin.is_verified = False
            self.app.central_userdb.save(user)
            assert user.identities.nin.is_verified is False

        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"nin": user.identities.nin.number, "csrf_token": sess.get_csrf_token()}
                if data1 is not None:
                    data.update(data1)

                return client.post("/remove-nin", data=json.dumps(data), content_type=self.content_type_json)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _remove_identity(self, mock_request_user_sync: Any, data1: Optional[dict[str, Any]] = None):
        """
        Send a POST request to remove all identities from the test user

        :param data1: to control the data that is POSTed
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities is not None
        assert user.identities.nin is not None

        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"identity_type": user.identities.nin.identity_type, "csrf_token": sess.get_csrf_token()}
                if data1 is not None:
                    data.update(data1)

                return client.post("/remove-identity", json=data)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _add_nin(
        self,
        mock_request_user_sync: Any,
        data1: Optional[dict[str, Any]] = None,
        remove: bool = True,
        unverify: bool = False,
    ):
        """
        Send a POST request to add a NIN to the test user, possibly removing it's primary, verified NIN.

        :param data1: to control the data that is POSTed
        :param remove: whether to actually remove the NIN from the test user before sending the request.
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True

        if unverify:
            user.identities.nin.is_verified = False
            self.app.central_userdb.save(user)
            assert user.identities.nin.is_verified is False

        if remove:
            user.identities.remove(ElementKey(IdentityType.NIN.value))
            self.app.central_userdb.save(user)
            assert user.identities.nin is None

        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"nin": self.test_user_nin, "csrf_token": sess.get_csrf_token()}
                if data1:
                    data.update(data1)

                return client.post("/add-nin", data=json.dumps(data), content_type=self.content_type_json)

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _refresh_user_data(
        self,
        mock_request_user_sync: Any,
        mock_get_all_navet_data: Any,
        user: User,
        navet_return_value: Optional[Any] = None,
    ):
        mock_request_user_sync.side_effect = self.request_user_sync
        if navet_return_value is None:
            mock_get_all_navet_data.return_value = self._get_all_navet_data()
        else:
            mock_get_all_navet_data.return_value = navet_return_value

        with self.session_cookie(self.browser, user.eppn) as client:
            with client.session_transaction() as sess:
                data = {"csrf_token": sess.get_csrf_token()}
            return client.post(
                "/refresh-official-user-data", data=json.dumps(data), content_type=self.content_type_json
            )

    def _get_credentials(self):
        response = self.browser.get("/credentials")
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.session_cookie(self.browser, eppn) as client:
            return client.get("/credentials")

    # actual tests

    def test_delete_account_no_csrf(self):
        data1 = {"csrf_token": ""}
        response = self._delete_account(data1=data1)
        self._check_error_response(
            response,
            type_="POST_SECURITY_TERMINATE_ACCOUNT_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    def test_delete_account_wrong_csrf(self):
        data1 = {"csrf_token": "wrong-token"}
        response = self._delete_account(data1=data1)
        self._check_error_response(
            response,
            type_="POST_SECURITY_TERMINATE_ACCOUNT_FAIL",
            error={"csrf_token": ["CSRF failed to validate"]},
        )

    def test_account_terminated_no_authn(self):
        response = self.browser.get("/terminate-account")
        self.assertEqual(response.status_code, 302)  # Redirect to token service

    def test_account_terminated_no_reauthn(self):
        response = self._delete_account()
        self._check_must_authenticate_response(
            response=response,
            type_="POST_SECURITY_TERMINATE_ACCOUNT_FAIL",
            frontend_action=FrontendAction.TERMINATE_ACCOUNT_AUTHN,
            authn_status=AuthnActionStatus.NOT_FOUND,
        )

    def test_account_terminated_stale(self):
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.TERMINATE_ACCOUNT_AUTHN,
            age=timedelta(seconds=1200),
        )
        response = self._delete_account()
        self._check_must_authenticate_response(
            response=response,
            type_="POST_SECURITY_TERMINATE_ACCOUNT_FAIL",
            frontend_action=FrontendAction.TERMINATE_ACCOUNT_AUTHN,
            authn_status=AuthnActionStatus.STALE,
        )

    def test_account_terminated(self):
        self.set_authn_action(
            eppn=self.test_user_eppn, frontend_action=FrontendAction.TERMINATE_ACCOUNT_AUTHN, age=timedelta(seconds=22)
        )
        response = self._delete_account()
        self._check_success_response(
            response,
            type_="POST_SECURITY_TERMINATE_ACCOUNT_SUCCESS",
            payload={"location": "https://test.localhost/services/authn/logout?next=https://eduid.se"},
        )
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert isinstance(user.terminated, datetime) is True

    def test_remove_nin(self):
        response = self._remove_nin(unverify=True)
        self._check_success_response(
            response,
            type_="POST_SECURITY_REMOVE_NIN_SUCCESS",
            msg=SecurityMsg.rm_success,
            payload={
                "identities": {
                    "is_verified": True,
                    "eidas": {"verified": True, "country_code": "DE", "date_of_birth": "1978-09-02"},
                    "svipe": {"verified": True, "country_code": "DE", "date_of_birth": "1978-09-02"},
                },
            },
        )

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is None

    def test_remove_not_existing_nin(self):
        response = self._remove_nin(data1={"nin": "202202031234"})
        assert self.test_user.identities.nin is not None
        self._check_success_response(
            response,
            type_="POST_SECURITY_REMOVE_NIN_SUCCESS",
            msg=SecurityMsg.rm_success,
            payload={
                "identities": {
                    "is_verified": True,
                    "nin": {"number": self.test_user.identities.nin.number, "verified": True},
                    "eidas": {"verified": True, "country_code": "DE", "date_of_birth": "1978-09-02"},
                    "svipe": {"verified": True, "country_code": "DE", "date_of_birth": "1978-09-02"},
                },
            },
        )
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True

    @patch("eduid.webapp.security.views.security.remove_nin_from_user")
    def test_remove_nin_am_fail(self, mock_remove: Any):
        from eduid.common.rpc.exceptions import AmTaskFailed

        mock_remove.side_effect = AmTaskFailed()
        response = self._remove_nin()

        self.assertTrue(self.get_response_payload(response)["message"], "Temporary technical problems")

    def test_remove_nin_no_csrf(self):
        data1 = {"csrf_token": ""}
        response = self._remove_nin(data1=data1)

        self.assertTrue(self.get_response_payload(response)["error"])

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True

    def test_remove_verified_nin(self):
        response = self._remove_nin()
        self._check_error_response(response, type_="POST_SECURITY_REMOVE_NIN_FAIL", msg=SecurityMsg.rm_verified)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True

    def test_add_nin(self):
        response = self._add_nin()

        self._check_success_response(
            response,
            type_="POST_SECURITY_ADD_NIN_SUCCESS",
            msg=SecurityMsg.add_success,
            payload={
                "identities": {
                    "is_verified": True,
                    "eidas": {"verified": True, "country_code": "DE", "date_of_birth": "1978-09-02"},
                    "nin": {"number": self.test_user_nin, "verified": False},
                    "svipe": {"verified": True, "country_code": "DE", "date_of_birth": "1978-09-02"},
                },
            },
        )

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is False

    def test_add_existing_nin(self):
        response = self._add_nin(remove=False)

        self.assertEqual(self.get_response_payload(response)["message"], "nins.already_exists")

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True

    def test_add_other_existing_unverified_nin(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is not None
        number_before = user.identities.nin.number
        data1 = {"nin": "202201023456"}
        response = self._add_nin(data1=data1, remove=False, unverify=True)

        self.assertEqual(self.get_response_payload(response)["message"], "nins.already_exists")

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is False
        assert user.identities.nin.number == number_before

    @patch("eduid.webapp.security.views.security.add_nin_to_user")
    def test_add_nin_task_failed(self, mock_add: MagicMock):
        from eduid.common.rpc.exceptions import AmTaskFailed

        mock_add.side_effect = AmTaskFailed()
        response = self._add_nin()

        self.assertEqual(self.get_response_payload(response)["message"], "Temporary technical problems")

    def test_add_nin_bad_csrf(self):
        data1 = {"csrf_token": "bad-token"}
        response = self._add_nin(data1=data1, remove=False)

        self.assertTrue(self.get_response_payload(response)["error"])

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True

    def test_add_invalid_nin(self):
        data1 = {"nin": "123456789"}
        response = self._add_nin(data1=data1, remove=False)
        self.assertIsNotNone(self.get_response_payload(response)["error"]["nin"])

        self._check_error_response(
            response,
            type_="POST_SECURITY_ADD_NIN_FAIL",
            error={"nin": ["nin needs to be formatted as 18|19|20yymmddxxxx"]},
        )
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True

    def test_remove_identity(self):
        self.set_authn_action(
            eppn=self.test_user_eppn, frontend_action=FrontendAction.REMOVE_IDENTITY, age=timedelta(seconds=22)
        )
        response = self._remove_identity()
        self._check_success_response(
            response,
            type_="POST_SECURITY_REMOVE_IDENTITY_SUCCESS",
            msg=SecurityMsg.rm_success,
            payload={
                "identities": {
                    "is_verified": True,
                    "eidas": {"verified": True, "country_code": "DE", "date_of_birth": "1978-09-02"},
                    "svipe": {"verified": True, "country_code": "DE", "date_of_birth": "1978-09-02"},
                },
            },
        )
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is None

    @patch("eduid.webapp.security.views.security.remove_identity_from_user")
    def test_remove_identity_am_fail(self, mock_remove: Any):
        from eduid.common.rpc.exceptions import AmTaskFailed

        mock_remove.side_effect = AmTaskFailed()
        response = self._remove_identity()

        self.assertTrue(self.get_response_payload(response)["message"], "Temporary technical problems")

    def test_remove_identity_no_csrf(self):
        data1 = {"csrf_token": ""}
        response = self._remove_identity(data1=data1)

        self.assertTrue(self.get_response_payload(response)["error"])

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True

    def test_refresh_user_official_name(self):
        """
        Refresh a verified users given name and surname from Navet data.
        Make sure the users display name do not change.
        """
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.given_name == "John"
        assert user.chosen_given_name is None
        assert user.surname == "Smith"
        assert user.legal_name is None

        response = self._refresh_user_data(user=user)
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.given_name == "Testaren Test"
        assert user.chosen_given_name == "Test"
        assert user.surname == "Testsson"
        assert user.legal_name == "Testaren Test Testsson"
        self._check_success_response(
            response,
            type_="POST_SECURITY_REFRESH_OFFICIAL_USER_DATA_SUCCESS",
            msg=SecurityMsg.user_updated,
        )

    def test_refresh_user_official_name_no_chosen_given_name(self):
        """
        Refresh a verified users given name and surname from Navet data.
        Make sure the users display name is set, using given name marking, from first name and surname if
        previously unset.
        """
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        user.chosen_given_name = None
        self.app.central_userdb.save(user)

        response = self._refresh_user_data(user=user)
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.given_name == "Testaren Test"
        assert user.surname == "Testsson"
        assert user.chosen_given_name == "Test"
        self._check_success_response(
            response,
            type_="POST_SECURITY_REFRESH_OFFICIAL_USER_DATA_SUCCESS",
            msg=SecurityMsg.user_updated,
        )

    def test_refresh_user_official_name_throttle(self):
        """
        Make two refreshes in succession before throttle_update_user_period has expired, make sure an error is returned.
        """
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        # Make two calls to update user endpoint
        self._refresh_user_data(user=user)
        response = self._refresh_user_data(user=user)
        self._check_error_response(
            response, type_="POST_SECURITY_REFRESH_OFFICIAL_USER_DATA_FAIL", msg=SecurityMsg.user_update_throttled
        )

    def test_refresh_user_official_name_user_not_verified(self):
        """
        Refresh an unverified users, make sure an error is returned.
        """
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        # Remove verified nin from the users
        user.identities.remove(ElementKey(IdentityType.NIN))
        self.app.central_userdb.save(user)
        response = self._refresh_user_data(user=user)
        self._check_error_response(
            response, type_="POST_SECURITY_REFRESH_OFFICIAL_USER_DATA_FAIL", msg=SecurityMsg.user_not_verified
        )

    def test_refresh_user_official_name_user_no_names_set(self):
        """
        Refresh a verified user with no names set (this can be true for old user objects).
        """
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        # Unset names from the users
        user.given_name = ""
        user.chosen_given_name = ""
        user.surname = ""
        user.legal_name = ""
        self.app.central_userdb.save(user)

        response = self._refresh_user_data(user=user)
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.given_name == "Testaren Test"
        assert user.chosen_given_name == "Test"
        assert user.surname == "Testsson"
        assert user.legal_name == "Testaren Test Testsson"
        self._check_success_response(
            response, type_="POST_SECURITY_REFRESH_OFFICIAL_USER_DATA_SUCCESS", msg=SecurityMsg.user_updated
        )

    def test_refresh_user_official_name_deregistered(self):
        mock_get_all_navet_data = self._get_all_navet_data()
        # add empty official address and deregistration information as for a user that has emigrated
        mock_get_all_navet_data.person.postal_addresses.official_address = OfficialAddress()
        mock_get_all_navet_data.person.deregistration_information = DeregistrationInformation(
            date="20220509", cause_code=DeregisteredCauseCode.EMIGRATED
        )

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.given_name == "John"
        assert user.chosen_given_name is None
        assert user.surname == "Smith"
        assert user.legal_name is None

        response = self._refresh_user_data(user=user, navet_return_value=mock_get_all_navet_data)
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.given_name == "Testaren Test"
        assert user.chosen_given_name == "Test"
        assert user.surname == "Testsson"
        assert user.legal_name == "Testaren Test Testsson"
        self._check_success_response(
            response,
            type_="POST_SECURITY_REFRESH_OFFICIAL_USER_DATA_SUCCESS",
            msg=SecurityMsg.user_updated,
        )

    def test_get_credentials(self):
        response = self._get_credentials()
        expected_payload = {
            "credentials": [
                {
                    "created_ts": "2013-09-02 10:23:25+00:00",
                    "credential_type": "security.password_credential_type",
                    "description": None,
                    "key": "112345678901234567890123",
                    "success_ts": None,
                    "used_for_login": False,
                    "verified": False,
                }
            ],
        }
        self._check_success_response(response, type_="GET_SECURITY_CREDENTIALS_SUCCESS", payload=expected_payload)
