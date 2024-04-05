import json
from typing import Any, Mapping, Optional
from unittest.mock import patch

from werkzeug.test import TestResponse

from eduid.userdb.element import ElementKey
from eduid.webapp.common.api.exceptions import ApiException
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.personal_data.app import PersonalDataApp, pd_init_app


class PersonalDataTests(EduidAPITestCase[PersonalDataApp]):
    def setUp(self, *args, **kwargs):
        super().setUp(*args, copy_user_to_private=True, **kwargs)

    def load_app(self, config: Mapping[str, Any]) -> PersonalDataApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return pd_init_app("testing", config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                "available_languages": {"en": "English", "sv": "Svenska"},
            }
        )
        return config

    # parameterized test methods

    def _get_user(self, eppn: Optional[str] = None):
        """
        Send a GET request to get the personal data of a user

        :param eppn: the eppn of the user
        """
        response = self.browser.get("/user")
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = eppn or self.test_user_data["eduPersonPrincipalName"]
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get("/user")

            return json.loads(response2.data)

    def _get_user_all_data(self, eppn: str) -> TestResponse:
        """
        Send a GET request to get all the data of a user

        :param eppn: the eppn of the user
        """
        response = self.browser.get("/all-user-data")
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        with self.session_cookie(self.browser, eppn) as client:
            return client.get("/all-user-data")

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _post_user(
        self, mock_request_user_sync: Any, mod_data: Optional[dict[str, Any]] = None, verified_user: bool = True
    ):
        """
        POST personal data for the test user
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data["eduPersonPrincipalName"]

        if not verified_user:
            # Remove verified identities from the users
            user = self.app.central_userdb.get_user_by_eppn(eppn)
            for identity in user.identities.verified:
                user.identities.remove(ElementKey(identity.identity_type.value))
            self.app.central_userdb.save(user)

        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "given_name": "Peter",
                        "surname": "Johnson",
                        "language": "en",
                        "csrf_token": sess.get_csrf_token(),
                    }
                if mod_data:
                    data.update(mod_data)
            return client.post("/user", data=json.dumps(data), content_type=self.content_type_json)

    def _get_user_identities(self, eppn: Optional[str] = None):
        """
        GET a list of all the identities of a user

        :param eppn: the eppn of the user
        """
        response = self.browser.get("/identities")
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = eppn or self.test_user_data["eduPersonPrincipalName"]
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get("/identities")
            return response2

    # actual test methods

    def test_get_user(self):
        user_data = self._get_user()
        self.assertEqual(user_data["type"], "GET_PERSONAL_DATA_USER_SUCCESS")
        self.assertEqual(user_data["payload"]["given_name"], "John")
        self.assertEqual(user_data["payload"]["surname"], "Smith")
        self.assertEqual(user_data["payload"]["language"], "en")
        # Check that unwanted data is not serialized
        self.assertIsNotNone(self.test_user.to_dict().get("passwords"))
        self.assertIsNone(user_data["payload"].get("passwords"))

    def test_get_unknown_user(self):
        with self.assertRaises(ApiException):
            self._get_user(eppn="fooo-fooo")

    def test_get_user_all_data(self):
        response = self._get_user_all_data(eppn="hubba-bubba")
        expected_payload = {
            "emails": [
                {"email": "johnsmith@example.com", "primary": True, "verified": True},
                {"email": "johnsmith2@example.com", "primary": False, "verified": False},
            ],
            "eppn": "hubba-bubba",
            "given_name": "John",
            "ladok": {
                "external_id": "00000000-1111-2222-3333-444444444444",
                "university": {"ladok_name": "DEV", "name": {"en": "Test University", "sv": "Testlärosäte"}},
            },
            "language": "en",
            "identities": {
                "is_verified": True,
                "nin": {"number": "197801011234", "verified": True},
                "eidas": {"verified": True, "country_code": "DE", "date_of_birth": "1978-09-02"},
                "svipe": {"verified": True, "country_code": "DE", "date_of_birth": "1978-09-02"},
            },
            "phones": [
                {"number": "+34609609609", "primary": True, "verified": True},
                {"number": "+34 6096096096", "primary": False, "verified": False},
            ],
            "surname": "Smith",
        }

        self._check_success_response(
            response=response, type_="GET_PERSONAL_DATA_ALL_USER_DATA_SUCCESS", payload=expected_payload
        )

        # Check that unwanted data is not serialized
        user_data = json.loads(response.data)
        assert self.test_user.to_dict().get("passwords") is not None
        assert user_data["payload"].get("passwords") is None

    def test_get_unknown_user_all_data(self):
        with self.assertRaises(ApiException):
            self._get_user_all_data(eppn="fooo-fooo")

    def test_post_user(self):
        response = self._post_user(verified_user=False)
        expected_payload = {
            "surname": "Johnson",
            "given_name": "Peter",
            "language": "en",
        }
        self._check_success_response(response, type_="POST_PERSONAL_DATA_USER_SUCCESS", payload=expected_payload)

        expected_payload = {
            "surname": "Smith",
            "given_name": "John",
            "language": "sv",
        }
        response = self._post_user(mod_data=expected_payload)
        self._check_success_response(response, type_="POST_PERSONAL_DATA_USER_SUCCESS", payload=expected_payload)

    def test_set_given_name_and_surname_verified_user(self):
        mod_data = {
            "surname": "Johnson",
            "given_name": "Peter",
            "language": "sv",
        }
        expected_payload = {
            "surname": "Smith",
            "given_name": "John",
            "language": "sv",
        }
        response = self._post_user(mod_data=mod_data)
        self._check_success_response(response, type_="POST_PERSONAL_DATA_USER_SUCCESS", payload=expected_payload)

    def test_post_user_bad_csrf(self):
        response = self._post_user(mod_data={"csrf_token": "wrong-token"})
        expected_payload = {"error": {"csrf_token": ["CSRF failed to validate"]}}
        self._check_error_response(response, type_="POST_PERSONAL_DATA_USER_FAIL", payload=expected_payload)

    def test_post_user_no_given_name(self):
        response = self._post_user(mod_data={"given_name": ""})
        expected_payload = {"error": {"given_name": ["pdata.field_required"]}}
        self._check_error_response(response, type_="POST_PERSONAL_DATA_USER_FAIL", payload=expected_payload)

    def test_post_user_blank_given_name(self):
        response = self._post_user(mod_data={"given_name": " "})
        expected_payload = {"error": {"given_name": ["pdata.field_required"]}}
        self._check_error_response(response, type_="POST_PERSONAL_DATA_USER_FAIL", payload=expected_payload)

    def test_post_user_no_surname(self):
        response = self._post_user(mod_data={"surname": ""})
        expected_payload = {"error": {"surname": ["pdata.field_required"]}}
        self._check_error_response(response, type_="POST_PERSONAL_DATA_USER_FAIL", payload=expected_payload)

    def test_post_user_blank_surname(self):
        response = self._post_user(mod_data={"surname": " "})
        expected_payload = {"error": {"surname": ["pdata.field_required"]}}
        self._check_error_response(response, type_="POST_PERSONAL_DATA_USER_FAIL", payload=expected_payload)

        expected_payload = {
            "surname": "Johnson",
            "given_name": "Peter",
            "language": "en",
        }
        self._check_success_response(response, type_="POST_PERSONAL_DATA_USER_SUCCESS", payload=expected_payload)


    def test_post_user_no_language(self):
        response = self._post_user(mod_data={"language": ""})
        expected_payload = {"error": {"language": ["Language '' is not available"]}}
        self._check_error_response(response, type_="POST_PERSONAL_DATA_USER_FAIL", payload=expected_payload)

    def test_post_user_unknown_language(self):
        response = self._post_user(mod_data={"language": "es"})
        expected_payload = {"error": {"language": ["Language 'es' is not available"]}}
        self._check_error_response(response, type_="POST_PERSONAL_DATA_USER_FAIL", payload=expected_payload)

    def test_get_user_identities(self):
        response = self._get_user_identities()
        expected_payload = {
            "identities": {
                "is_verified": True,
                "nin": {"number": "197801011234", "verified": True},
                "eidas": {"verified": True, "country_code": "DE", "date_of_birth": "1978-09-02"},
                "svipe": {"verified": True, "country_code": "DE", "date_of_birth": "1978-09-02"},
            },
        }
        self._check_success_response(response, type_="GET_PERSONAL_DATA_IDENTITIES_SUCCESS", payload=expected_payload)

        params = [
            # random names from Skatteverket test list
        ]
        for param in params:
