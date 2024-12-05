import json
from datetime import date, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

from flask import url_for
from iso3166 import Country, countries
from werkzeug.test import TestResponse

from eduid.common.config.base import FrontendAction
from eduid.common.misc.timeutil import utc_now
from eduid.userdb.identity import FrejaIdentity, FrejaRegistrationLevel, IdentityProofingMethod
from eduid.userdb.testing import SetupConfig
from eduid.webapp.common.api.messages import CommonMsg
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.common.proofing.testing import ProofingTests
from eduid.webapp.freja_eid.app import FrejaEIDApp, freja_eid_init_app
from eduid.webapp.freja_eid.helpers import (
    FrejaDocument,
    FrejaDocumentType,
    FrejaEIDDocumentUserInfo,
    FrejaEIDMsg,
    FrejaEIDTokenResponse,
)

__author__ = "lundberg"


class FrejaEIDTests(ProofingTests[FrejaEIDApp]):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self, config: SetupConfig | None = None) -> None:
        if config is None:
            config = SetupConfig()
        config.users = ["hubba-bubba", "hubba-baar"]
        super().setUp(config=config)

        self.unverified_test_user = self.app.central_userdb.get_user_by_eppn("hubba-baar")
        self._user_setup()

        self.default_frontend_data = {
            "method": "freja_eid",
            "frontend_action": "verifyIdentity",
            "frontend_state": "test_state",
        }

        self.oidc_provider_config = {
            "response_types_supported": ["code"],
            "request_parameter_supported": True,
            "request_uri_parameter_supported": False,
            "userinfo_encryption_alg_values_supported": ["none"],
            "claims_parameter_supported": False,
            "grant_types_supported": ["authorization_code"],
            "scopes_supported": [
                "openid",
                "email",
                "profile",
                "https://frejaeid.com/oidc/scopes/age",
                "https://frejaeid.com/oidc/scopes/personalIdentityNumber",
                "https://frejaeid.com/oidc/scopes/organisationId",
                "phone",
                "https://frejaeid.com/oidc/scopes/allPhoneNumbers",
                "https://frejaeid.com/oidc/scopes/covidCertificate",
                "https://frejaeid.com/oidc/scopes/document",
                "https://frejaeid.com/oidc/scopes/registrationLevel",
                "https://frejaeid.com/oidc/scopes/allEmailAddresses",
                "https://frejaeid.com/oidc/scopes/relyingPartyUserId",
                "https://frejaeid.com/oidc/scopes/integratorSpecificUserId",
                "https://frejaeid.com/oidc/scopes/customIdentifier",
                "https://frejaeid.com/oidc/scopes/addresses",
                "address",
            ],
            "issuer": "https://example.com/op/oidc/",
            "authorization_endpoint": "https://example.com/op/oidc/authorize",
            "userinfo_endpoint": "https://example.com/op/oidc/userinfo",
            "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
            "userinfo_signing_alg_values_supported": ["none"],
            "claims_supported": [
                "email",
                "email_verified",
                "name",
                "given_name",
                "family_name",
                "https://frejaeid.com/oidc/claims/age",
                "https://frejaeid.com/oidc/claims/personalIdentityNumber",
                "https://frejaeid.com/oidc/claims/country",
                "https://frejaeid.com/oidc/claims/organisationIdIdentifier",
                "https://frejaeid.com/oidc/claims/organisationIdAdditionalAttributes",
                "phone_number",
                "phone_number_verified",
                "https://frejaeid.com/oidc/claims/allPhoneNumbers",
                "https://frejaeid.com/oidc/claims/covidCertificate",
                "https://frejaeid.com/oidc/claims/document",
                "https://frejaeid.com/oidc/claims/registrationLevel",
                "https://frejaeid.com/oidc/claims/allEmailAddresses",
                "https://frejaeid.com/oidc/claims/relyingPartyUserId",
                "https://frejaeid.com/oidc/claims/integratorSpecificUserId",
                "https://frejaeid.com/oidc/claims/customIdentifier",
                "https://frejaeid.com/oidc/claims/addresses",
                "address",
            ],
            "require_request_uri_registration": True,
            "code_challenge_methods_supported": ["plain", "S256"],
            "jwks_uri": "https://example.com/op/oidc/jwk",
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "claim_types_supported": ["normal"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "request_object_signing_alg_values_supported": ["RS256", "none"],
            "request_object_encryption_alg_values_supported": ["RSA1_5", "RSA-OAEP-256"],
            "token_endpoint": "https://example.com/op/oidc/token",
        }

    def load_app(self, config: dict[str, Any]) -> FrejaEIDApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return freja_eid_init_app("testing", config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                "freja_eid_client": {
                    "client_id": "test_client_id",
                    "client_secret": "test_client_secret",
                    "issuer": "https://example.com/op/oidc",
                },
                "frontend_action_authn_parameters": {
                    FrontendAction.VERIFY_IDENTITY.value: {
                        "force_authn": True,
                        "finish_url": "https://dashboard.example.com/profile/ext-return/{app_name}/{authn_id}",
                    },
                },
            }
        )
        return config

    def _user_setup(self) -> None:
        # remove any freja eid identity that already exists, we want to handle those ourselves
        for eppn in [self.test_user.eppn, self.unverified_test_user.eppn]:
            user = self.app.central_userdb.get_user_by_eppn(eppn)
            if user.identities.freja:
                user.identities.remove(user.identities.freja.key)
                self.app.central_userdb.save(user)

    @staticmethod
    def get_mock_userinfo(
        issuing_country: Country,
        personal_identity_number: str | None = "123456789",
        registration_level: FrejaRegistrationLevel = FrejaRegistrationLevel.EXTENDED,
        birthdate: date = date(year=1901, month=2, day=3),
        freja_user_id: str = "unique_freja_eid",
        transaction_id: str = "unique_transaction_id",
        given_name: str = "Test",
        family_name: str = "Testsson",
        now: datetime = utc_now(),
        userinfo_expires: datetime | None = None,
        document_expires: datetime | None = None,
    ) -> FrejaEIDDocumentUserInfo:
        if userinfo_expires is None:
            userinfo_expires = now + timedelta(minutes=5)
        if document_expires is None:
            document_expires = now + timedelta(days=1095)  # 3 years

        return FrejaEIDDocumentUserInfo(
            aud="test",
            exp=int(userinfo_expires.timestamp()),
            iat=int(now.timestamp()),
            iss="test",
            sub=freja_user_id,
            date_of_birth=birthdate,
            family_name=family_name,
            given_name=given_name,
            name=f"{given_name} {family_name}",
            country=issuing_country.alpha2,
            document=FrejaDocument(
                type=FrejaDocumentType.PASSPORT,
                country=issuing_country.alpha2,
                serial_number="1234567890",
                expiration_date=document_expires.date(),
            ),
            personal_identity_number=personal_identity_number,
            user_id=freja_user_id,
            registration_level=registration_level,
            transaction_id=transaction_id,
        )

    @staticmethod
    def _get_state_and_nonce(auth_url: str) -> tuple[str, str]:
        auth_url_query = urlparse(auth_url).query
        return parse_qs(auth_url_query)["state"][0], parse_qs(auth_url_query)["nonce"][0]

    @patch("authlib.integrations.requests_client.oauth2_session.OAuth2Session.request")
    @patch("authlib.integrations.base_client.sync_openid.OpenIDMixin.parse_id_token")
    @patch("authlib.integrations.base_client.sync_openid.OpenIDMixin.userinfo")
    @patch("authlib.integrations.base_client.sync_app.OAuth2Mixin.fetch_access_token")
    @patch("authlib.integrations.base_client.sync_app.OAuth2Mixin.load_server_metadata")
    def mock_authorization_callback(
        self,
        mock_metadata: MagicMock,
        mock_fetch_access_token: MagicMock,
        mock_userinfo: MagicMock,
        mock_parse_id_token: MagicMock,
        mock_end_session: MagicMock,
        state: str,
        nonce: str,
        userinfo: FrejaEIDDocumentUserInfo,
    ) -> TestResponse:
        with self.app.test_request_context():
            endpoint = url_for("freja_eid.authn_callback")

        mock_metadata.return_value = self.oidc_provider_config
        mock_end_session.return_value = True

        id_token = json.dumps(
            {
                "nonce": nonce,
                "sub": "sub",
                "iss": "iss",
                "aud": ["aud"],
                "exp": userinfo.exp,
                "iat": userinfo.iat,
                "auth_time": userinfo.iat,
                "acr": "acr",
                "amr": ["amr"],
                "azp": "azp",
            }
        )
        mock_fetch_access_token.return_value = {
            "access_token": "access_token",
            "token_type": "token_type",
            "expires_in": timedelta(minutes=5).total_seconds(),
            "expires_at": userinfo.exp,
            "refresh_token": "refresh_token",
            "id_token": id_token,
        }

        mock_parse_id_token.return_value = userinfo.model_dump()
        mock_userinfo.return_value = userinfo.model_dump()
        return self.browser.get(f"{endpoint}?id_token=id_token&state={state}&code=mock_code")

    @patch("authlib.integrations.base_client.sync_app.OAuth2Mixin.load_server_metadata")
    def _start_auth(self, mock_metadata: MagicMock, endpoint: str, data: dict[str, Any], eppn: str) -> TestResponse:
        mock_metadata.return_value = self.oidc_provider_config

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            _data = {
                "csrf_token": csrf_token,
            }
            _data.update(data)
            return client.post(endpoint, json=_data)

    def test_app_starts(self) -> None:
        assert self.app.conf.app_name == "testing"

    @staticmethod
    def test_parse_token_response() -> None:
        token_response_swedish = {
            "access_token": "access_token",
            "token_type": "Bearer",
            "expires_in": 599,
            "scope": "space delimited scopes",
            "id_token": "id_token",
            "expires_at": 1726060986,
            "userinfo": {
                "sub": "subject_identifier",
                "https://frejaeid.com/oidc/claims/country": "SE",
                "birthdate": "1981-07-01",
                "kid": "oidc_signing_kid",
                "iss": "https://eid-provider.example.com/oidc/",
                "https://frejaeid.com/oidc/claims/registrationLevel": "PLUS",
                "https://frejaeid.com/oidc/claims/personalIdentityNumber": "198107011481",
                "given_name": "Sven",
                "nonce": "some_nonce",
                "aud": "test",
                "name": "Sven Svensson",
                "https://frejaeid.com/oidc/claims/document": {
                    "type": "PASS",
                    "country": "SE",
                    "serialNumber": "791840288",
                    "expirationDate": "2029-09-11",
                },
                "https://frejaeid.com/oidc/claims/relyingPartyUserId": "relying_party_user_id",
                "exp": 1726063987,
                "https://frejaeid.com/oidc/claims/transactionReference": "transaction_reference",
                "iat": 1726060387,
                "family_name": "Svensson",
                "jti": "61ec03e5-ec08-4ac2-bd54-6256994fb784",
            },
        }
        parsed_token_response = FrejaEIDTokenResponse(**token_response_swedish)
        assert parsed_token_response is not None
        assert parsed_token_response.userinfo is not None
        assert parsed_token_response.userinfo.iss == "https://eid-provider.example.com/oidc/"
        assert parsed_token_response.userinfo.aud == "test"
        assert parsed_token_response.userinfo.registration_level == FrejaRegistrationLevel.PLUS
        assert parsed_token_response.userinfo.personal_identity_number == "198107011481"
        assert parsed_token_response.userinfo.name == "Sven Svensson"
        assert parsed_token_response.userinfo.family_name == "Svensson"
        assert parsed_token_response.userinfo.given_name == "Sven"
        assert parsed_token_response.userinfo.date_of_birth == date(year=1981, month=7, day=1)
        assert parsed_token_response.userinfo.document is not None
        assert parsed_token_response.userinfo.document.type == FrejaDocumentType.PASSPORT
        assert parsed_token_response.userinfo.document.country == "SE"
        assert parsed_token_response.userinfo.document.serial_number == "791840288"
        assert parsed_token_response.userinfo.document.expiration_date == date(year=2029, month=9, day=11)
        assert parsed_token_response.userinfo.transaction_id == "transaction_reference"
        assert parsed_token_response.userinfo.user_id == "relying_party_user_id"

    def test_authenticate(self) -> None:
        response = self.browser.get("/")
        self.assertEqual(response.status_code, 401)
        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            response = browser.get("/")
        self._check_success_response(response, type_="GET_FREJA_EID_SUCCESS")

    def test_verify_identity_request(self) -> None:
        with self.app.test_request_context():
            endpoint = url_for("freja_eid.verify_identity")

        response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=self.test_user.eppn)
        assert response.status_code == 200
        self._check_success_response(response, type_="POST_FREJA_EID_VERIFY_IDENTITY_SUCCESS")
        assert self.get_response_payload(response)["location"].startswith("https://example.com/op/oidc/authorize")
        query: dict[str, list[str]] = parse_qs(urlparse(self.get_response_payload(response)["location"]).query)
        assert query["response_type"] == ["code"]
        assert query["client_id"] == ["test_client_id"]
        assert query["redirect_uri"] == ["http://test.localhost/authn-callback"]
        assert query["scope"] == [
            " ".join(self.app.conf.freja_eid_client.scopes)
        ], f"{query['scope']} != {[' '.join(self.app.conf.freja_eid_client.scopes)]}"
        assert query["code_challenge_method"] == ["S256"]

    @patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_nin_identity(self, mock_request_user_sync: MagicMock, mock_reference_nin: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_reference_nin.return_value = None

        eppn = self.unverified_test_user.eppn
        country = countries.get("Sweden")

        with self.app.test_request_context():
            endpoint = url_for("freja_eid.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])

        userinfo = self.get_mock_userinfo(issuing_country=country, registration_level=FrejaRegistrationLevel.PLUS)
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_msg=FrejaEIDMsg.identity_verify_success,
        )

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        self._verify_user_parameters(
            eppn,
            identity_verified=True,
            num_proofings=1,
            num_mfa_tokens=0,
            locked_identity=user.identities.nin,
            proofing_method=IdentityProofingMethod.FREJA_EID,
            proofing_version=self.app.conf.freja_eid_proofing_version,
        )

        # check names
        assert user.given_name == userinfo.given_name
        assert user.surname == userinfo.family_name
        # check proofing log
        doc = self.app.proofing_log._get_documents_by_attr(attr="eduPersonPrincipalName", value=eppn)[0]
        assert doc["given_name"] == userinfo.given_name
        assert doc["surname"] == userinfo.family_name

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_foreign_identity(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.unverified_test_user.eppn
        country = countries.get("Denmark")

        with self.app.test_request_context():
            endpoint = url_for("freja_eid.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country)
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_msg=FrejaEIDMsg.identity_verify_success,
        )

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        self._verify_user_parameters(
            eppn,
            identity_verified=True,
            num_proofings=1,
            num_mfa_tokens=0,
            locked_identity=user.identities.freja,
            proofing_method=IdentityProofingMethod.FREJA_EID,
            proofing_version=self.app.conf.freja_eid_proofing_version,
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_foreign_identity_no_identity_number(self, mock_request_user_sync: MagicMock) -> None:
        """Not all countries have something like a Swedish NIN, so personal_identity_number may be None"""
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.unverified_test_user.eppn
        country = countries.get("Denmark")

        with self.app.test_request_context():
            endpoint = url_for("freja_eid.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country, personal_identity_number=None)
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_msg=FrejaEIDMsg.identity_verify_success,
        )

        user = self.app.central_userdb.get_user_by_eppn(eppn)

        assert user.identities.freja is not None
        assert user.identities.freja.personal_identity_number is None

        self._verify_user_parameters(
            eppn,
            identity_verified=True,
            num_proofings=1,
            num_mfa_tokens=0,
            locked_identity=user.identities.freja,
            proofing_method=IdentityProofingMethod.FREJA_EID,
            proofing_version=self.app.conf.freja_eid_proofing_version,
        )

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_nin_identity_already_verified(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock
    ) -> None:
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        country = countries.get("Sweden")

        with self.app.test_request_context():
            endpoint = url_for("freja_eid.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country)
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_error=True,
            expect_msg=ProofingMsg.identity_already_verified,
        )
        self._verify_user_parameters(eppn, identity_verified=True, num_proofings=0, num_mfa_tokens=0)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_foreign_identity_already_verified(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        country = countries.get("Denmark")

        # add a verified freja eid identity
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        userinfo = self.get_mock_userinfo(issuing_country=country)
        user.identities.add(
            FrejaIdentity(
                personal_identity_number=userinfo.personal_identity_number,
                country_code=country.alpha2,
                date_of_birth=datetime.combine(userinfo.date_of_birth, datetime.min.time()),
                is_verified=True,
                user_id=userinfo.user_id,
                registration_level=userinfo.registration_level,
            )
        )
        self.request_user_sync(user)

        with self.app.test_request_context():
            endpoint = url_for("freja_eid.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country)
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_error=True,
            expect_msg=ProofingMsg.identity_already_verified,
        )
        self._verify_user_parameters(eppn, identity_verified=True, num_proofings=0, num_mfa_tokens=0)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_foreign_identity_replace_locked_identity(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        country = countries.get("Denmark")

        # add a locked freja eid identity that will match the new identity
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        userinfo = self.get_mock_userinfo(issuing_country=country)
        user.locked_identity.add(
            FrejaIdentity(
                personal_identity_number=userinfo.personal_identity_number,
                country_code="DK",
                date_of_birth=datetime.combine(userinfo.date_of_birth, datetime.min.time()),
                is_verified=True,
                user_id="another_freja_eid",
                registration_level=userinfo.registration_level,
            )
        )
        user.given_name = userinfo.given_name
        user.surname = userinfo.family_name
        self.app.central_userdb.save(user)

        with self.app.test_request_context():
            endpoint = url_for("freja_eid.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_msg=FrejaEIDMsg.identity_verify_success,
        )
        new_locked_identity = FrejaIdentity(
            personal_identity_number=userinfo.personal_identity_number,
            country_code="DK",
            date_of_birth=datetime.combine(userinfo.date_of_birth, datetime.min.time()),
            user_id=userinfo.user_id,
            registration_level=userinfo.registration_level,
        )
        self._verify_user_parameters(
            eppn, identity_verified=True, num_proofings=1, num_mfa_tokens=0, locked_identity=new_locked_identity
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_foreign_identity_replace_locked_identity_fail(self, mock_request_user_sync: MagicMock) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.unverified_test_user.eppn
        country = countries.get("Denmark")

        userinfo = self.get_mock_userinfo(issuing_country=country)

        # add a locked freja eid identity that will NOT match the new identity
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        user.locked_identity.add(
            FrejaIdentity(
                personal_identity_number=userinfo.personal_identity_number,
                country_code=userinfo.document.country,
                date_of_birth=datetime.today(),  # not matching the new identity
                is_verified=True,
                user_id="another_freja_eid",
                registration_level=userinfo.registration_level,
            )
        )
        self.app.central_userdb.save(user)

        with self.app.test_request_context():
            endpoint = url_for("freja_eid.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country)
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_error=True,
            expect_msg=CommonMsg.locked_identity_not_matching,
        )
        self._verify_user_parameters(
            eppn, identity_verified=False, num_proofings=0, num_mfa_tokens=0, locked_identity=user.locked_identity.freja
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_foreign_identity_replace_locked_identity_fail_personal_id_number(
        self, mock_request_user_sync: MagicMock
    ) -> None:
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.unverified_test_user.eppn
        country = countries.get("Denmark")
        personal_identity_number = "1234567890"
        other_admin_number = "0987654321"

        userinfo = self.get_mock_userinfo(issuing_country=country, personal_identity_number=personal_identity_number)

        # add a locked freja eid identity that will NOT match the new identity
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        user.locked_identity.add(
            FrejaIdentity(
                personal_identity_number=other_admin_number,  # not matching the new identity
                country_code=userinfo.document.country,
                date_of_birth=datetime.combine(userinfo.date_of_birth, datetime.min.time()),
                is_verified=True,
                user_id="another_freja_eid",
                registration_level=userinfo.registration_level,
            )
        )
        self.app.central_userdb.save(user)

        with self.app.test_request_context():
            endpoint = url_for("freja_eid.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country)
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_error=True,
            expect_msg=CommonMsg.locked_identity_not_matching,
        )
        self._verify_user_parameters(
            eppn, identity_verified=False, num_proofings=0, num_mfa_tokens=0, locked_identity=user.locked_identity.freja
        )

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_foreign_identity_already_verified_nin(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock
    ) -> None:
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        country = countries.get("Denmark")

        with self.app.test_request_context():
            endpoint = url_for("freja_eid.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country)
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_msg=FrejaEIDMsg.identity_verify_success,
        )
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        self._verify_user_parameters(
            eppn, identity_verified=True, num_proofings=1, num_mfa_tokens=0, locked_identity=user.identities.freja
        )
        self._verify_user_parameters(
            eppn, identity_verified=True, num_proofings=1, num_mfa_tokens=0, locked_identity=user.identities.nin
        )

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_identity_expired_document(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock
    ) -> None:
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.unverified_test_user.eppn
        country = countries.get("Sweden")

        with self.app.test_request_context():
            endpoint = url_for("freja_eid.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        yesterday = utc_now() - timedelta(days=1)
        userinfo = self.get_mock_userinfo(issuing_country=country, document_expires=yesterday)
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_error=True,
            expect_msg=ProofingMsg.session_info_not_valid,
        )
        self._verify_user_parameters(eppn, identity_verified=False, num_proofings=0, num_mfa_tokens=0)
