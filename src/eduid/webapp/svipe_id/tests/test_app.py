import json
from datetime import date, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

from flask import url_for
from iso3166 import Country, countries

from eduid.common.config.base import FrontendAction
from eduid.common.misc.timeutil import utc_now
from eduid.userdb import SvipeIdentity
from eduid.userdb.identity import IdentityProofingMethod
from eduid.webapp.common.api.messages import CommonMsg
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.common.proofing.testing import ProofingTests
from eduid.webapp.svipe_id.app import SvipeIdApp, svipe_id_init_app
from eduid.webapp.svipe_id.helpers import SvipeDocumentUserInfo, SvipeIDMsg
from eduid.webapp.svipe_id.settings.common import SvipeClientConfig

__author__ = "lundberg"


class SvipeIdTests(ProofingTests[SvipeIdApp]):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs, users=["hubba-bubba", "hubba-baar"])

        self.unverified_test_user = self.app.central_userdb.get_user_by_eppn("hubba-baar")
        self._user_setup()

        self.default_frontend_data = {
            "method": "svipe_id",
            "frontend_action": "verifyIdentity",
            "frontend_state": "test_state",
        }

        self.oidc_provider_config = {
            "issuer": "https://example.com/op/",
            "authorization_endpoint": "https://example.com/op/authorize",
            "token_endpoint": "https://example.com/op/token",
            "userinfo_endpoint": "https://example.com/op/userinfo",
            "jwks_uri": "https://example.com/op/keys",
            "registration_endpoint": "https://example.com/op/clients",
            "scopes_supported": ["openid", "profile", "email", "phone", "document", "document_full"],
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "id_token token",
                "code id_token",
                "code token",
                "code id_token token",
                "none",
            ],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "revocation_endpoint": "https://example.com/op/token/revoke",
            "end_session_endpoint": "https://example.com/op/logout",
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            "claims_supported": [
                "iss",
                "ver",
                "sub",
                "aud",
                "iat",
                "exp",
                "jti",
                "auth_time",
                "amr",
                "idp",
                "nonce",
                "at_hash",
                "c_hashname",
                "given_name",
                "family_name",
                "email",
                "email_verified",
                "phone_number",
                "phone_number_verified",
                "gender",
                "birthdate",
                "updated_at",
                "locale",
                "com.svipe:svipeid",
                "com.svipe:document_portrait",
                "com.svipe:document_nationality",
                "com.svipe:document_nationality_en",
                "com.svipe:document_type",
                "com.svipe:document_type_sdn",
                "com.svipe:document_type_sdn_en",
                "com.svipe:document_number",
                "com.svipe:document_issuing_country",
                "com.svipe:document_issuing_country_en",
                "com.svipe:document_expiry_date",
                "com.svipe:document_administrative_number",
            ],
            "backchannel_logout_supported": True,
            "backchannel_logout_session_supported": True,
            "frontchannel_logout_supported": True,
            "frontchannel_logout_session_supported": True,
            "claims_parameter_supported": True,
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
            "request_object_signing_alg_values_supported": ["RS256"],
            "userinfo_signing_alg_values_supported": ["RS256"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "acr_values_supported": ["face_present", "document_present", "face_and_document_present"],
        }

    def load_app(self, config: dict[str, Any]) -> SvipeIdApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return svipe_id_init_app("testing", config)

    def update_config(self, config: dict[str, Any]):
        config.update(
            {
                "svipe_client": {
                    "client_id": "test_client_id",
                    "client_secret": "test_client_secret",
                    "issuer": "https://issuer.example.com",
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

    def _user_setup(self):
        # remove any svipe identity that already exists, we want to handle those ourselves
        for eppn in [self.test_user.eppn, self.unverified_test_user.eppn]:
            user = self.app.central_userdb.get_user_by_eppn(eppn)
            if user.identities.svipe:
                user.identities.remove(user.identities.svipe.key)
                self.app.central_userdb.save(user)

    @staticmethod
    def get_mock_userinfo(
        issuing_country: Country,
        nationality: Country,
        administrative_number: str | None = "123456789",
        birthdate: date = date(year=1901, month=2, day=3),
        svipe_id: str = "unique_svipe_id",
        transaction_id: str = "unique_transaction_id",
        given_name: str = "Test",
        family_name: str = "Testsson",
        now: datetime = utc_now(),
        userinfo_expires: datetime | None = None,
        document_expires: datetime | None = None,
    ) -> SvipeDocumentUserInfo:
        if userinfo_expires is None:
            userinfo_expires = now + timedelta(minutes=5)
        if document_expires is None:
            document_expires = now + timedelta(days=1095)  # 3 years

        return SvipeDocumentUserInfo(
            at_hash="test",
            aud="test",
            auth_time=int(now.timestamp()),
            c_hash="test",
            exp=int(userinfo_expires.timestamp()),
            iat=int(now.timestamp()),
            iss="test",
            nbf=int(now.timestamp()),
            sid="test",
            sub=svipe_id,
            birthdate=birthdate,
            family_name=family_name,
            given_name=given_name,
            document_administrative_number=administrative_number,
            document_expiry_date=document_expires.date(),
            document_type_sdn_en="Passport",
            document_issuing_country=issuing_country.alpha3,
            document_nationality=nationality.alpha3,
            document_number="1234567890",
            svipe_id=svipe_id,
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
        userinfo: SvipeDocumentUserInfo,
    ):
        with self.app.test_request_context():
            endpoint = url_for("svipe_id.authn_callback")

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

        mock_parse_id_token.return_value = userinfo.dict()
        mock_userinfo.return_value = userinfo.dict()
        return self.browser.get(f"{endpoint}?id_token=id_token&state={state}&code=mock_code")

    @patch("authlib.integrations.base_client.sync_app.OAuth2Mixin.load_server_metadata")
    def _start_auth(self, mock_metadata: MagicMock, endpoint: str, data: dict[str, Any], eppn: str):
        mock_metadata.return_value = self.oidc_provider_config

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            _data = {
                "csrf_token": csrf_token,
            }
            _data.update(data)
            return client.post(endpoint, json=_data)

    def test_app_starts(self):
        assert self.app.conf.app_name == "testing"

    def test_client_claims_config(self):
        data = {
            "svipe_client": {
                "client_id": "x",
                "client_secret": "y",
                "issuer": "https://issuer.example.edu/",
                "claims_request": {
                    "com.svipe:document_administrative_number": {"essential": True},
                    "com.svipe:document_expiry_date": {"essential": True},
                    "com.svipe:document_issuing_country": {"essential": True},
                    "com.svipe:document_nationality": {"essential": True},
                    "com.svipe:document_number": {"essential": True},
                    "birthdate": {"essential": True},
                    "com.svipe:document_type_sdn_en": {"essential": True},
                    "com.svipe:meta_transaction_id": {"essential": True},
                    "com.svipe:svipeid": {"essential": True},
                    "family_name": {"essential": True},
                    "given_name": {"essential": True},
                    "name": None,
                },
            },
        }
        cfg = SvipeClientConfig.model_validate(data["svipe_client"])
        assert cfg.claims_request == data["svipe_client"]["claims_request"]

    def test_authenticate(self):
        response = self.browser.get("/")
        self.assertEqual(response.status_code, 401)
        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            response = browser.get("/")
        self._check_success_response(response, type_="GET_SVIPE_ID_SUCCESS")

    def test_verify_identity_request(self):
        with self.app.test_request_context():
            endpoint = url_for("svipe_id.verify_identity")

        response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=self.test_user.eppn)
        assert response.status_code == 200
        self._check_success_response(response, type_="POST_SVIPE_ID_VERIFY_IDENTITY_SUCCESS")
        assert self.get_response_payload(response)["location"].startswith("https://example.com/op/authorize")
        query: dict[str, list[str]] = parse_qs(urlparse(self.get_response_payload(response)["location"]).query)  # type: ignore
        assert query["response_type"] == ["code"]
        assert query["client_id"] == ["test_client_id"]
        assert query["redirect_uri"] == ["http://test.localhost/authn-callback"]
        assert query["scope"] == ["openid"]
        assert query["code_challenge_method"] == ["S256"]
        assert query["acr_values"] == ["face_present"]
        assert query["claims"] == [json.dumps({"userinfo": self.app.conf.svipe_client.claims_request})]

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_nin_identity(self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.unverified_test_user.eppn
        country = countries.get("Sweden")

        with self.app.test_request_context():
            endpoint = url_for("svipe_id.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])

        userinfo = self.get_mock_userinfo(issuing_country=country, nationality=country)
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_msg=SvipeIDMsg.identity_verify_success,
        )

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        self._verify_user_parameters(
            eppn,
            identity_verified=True,
            num_proofings=1,
            num_mfa_tokens=0,
            locked_identity=user.identities.nin,
            proofing_method=IdentityProofingMethod.SVIPE_ID,
            proofing_version=self.app.conf.svipe_id_proofing_version,
        )

        # check names
        assert user.given_name == userinfo.given_name
        assert user.surname == userinfo.family_name
        # check proofing log
        doc = self.app.proofing_log._get_documents_by_attr(attr="eduPersonPrincipalName", value=eppn)[0]
        assert doc["given_name"] == userinfo.given_name
        assert doc["surname"] == userinfo.family_name

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_foreign_identity(self, mock_request_user_sync: MagicMock):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.unverified_test_user.eppn
        country = countries.get("Denmark")

        with self.app.test_request_context():
            endpoint = url_for("svipe_id.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country, nationality=country)
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_msg=SvipeIDMsg.identity_verify_success,
        )

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        self._verify_user_parameters(
            eppn,
            identity_verified=True,
            num_proofings=1,
            num_mfa_tokens=0,
            locked_identity=user.identities.svipe,
            proofing_method=IdentityProofingMethod.SVIPE_ID,
            proofing_version=self.app.conf.svipe_id_proofing_version,
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_foreign_identity_no_admin_number(self, mock_request_user_sync: MagicMock):
        """Not all countries have something like a Swedish NIN, so administrative_number may be None"""
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.unverified_test_user.eppn
        country = countries.get("Denmark")

        with self.app.test_request_context():
            endpoint = url_for("svipe_id.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country, nationality=country, administrative_number=None)
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_msg=SvipeIDMsg.identity_verify_success,
        )

        user = self.app.central_userdb.get_user_by_eppn(eppn)

        assert user.identities.svipe is not None
        assert user.identities.svipe.administrative_number is None

        self._verify_user_parameters(
            eppn,
            identity_verified=True,
            num_proofings=1,
            num_mfa_tokens=0,
            locked_identity=user.identities.svipe,
            proofing_method=IdentityProofingMethod.SVIPE_ID,
            proofing_version=self.app.conf.svipe_id_proofing_version,
        )

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_nin_identity_already_verified(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock
    ):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        country = countries.get("Sweden")

        with self.app.test_request_context():
            endpoint = url_for("svipe_id.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country, nationality=country)
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
    def test_verify_foreign_identity_already_verified(self, mock_request_user_sync: MagicMock):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        country = countries.get("Denmark")

        # add a verified svipe identity
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        userinfo = self.get_mock_userinfo(issuing_country=country, nationality=country)
        user.identities.add(
            SvipeIdentity(
                administrative_number=userinfo.document_administrative_number,
                country_code=country.alpha2,
                date_of_birth=datetime.combine(userinfo.birthdate.today(), datetime.min.time()),
                is_verified=True,
                svipe_id=userinfo.svipe_id,
            )
        )
        self.request_user_sync(user)

        with self.app.test_request_context():
            endpoint = url_for("svipe_id.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country, nationality=country)
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
    def test_verify_foreign_identity_replace_locked_identity(self, mock_request_user_sync: MagicMock):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        country = countries.get("Denmark")

        # add a locked svipe identity that will match the new identity
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        userinfo = self.get_mock_userinfo(issuing_country=country, nationality=country)
        user.locked_identity.add(
            SvipeIdentity(
                administrative_number=userinfo.document_administrative_number,
                country_code="DK",
                date_of_birth=datetime.combine(userinfo.birthdate, datetime.min.time()),
                is_verified=True,
                svipe_id="another_svipe_id",
            )
        )
        user.given_name = userinfo.given_name
        user.surname = userinfo.family_name
        self.app.central_userdb.save(user)

        with self.app.test_request_context():
            endpoint = url_for("svipe_id.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_msg=SvipeIDMsg.identity_verify_success,
        )
        new_locked_identity = SvipeIdentity(
            administrative_number=userinfo.document_administrative_number,
            country_code="DK",
            date_of_birth=datetime.combine(userinfo.birthdate.today(), datetime.min.time()),
            svipe_id=userinfo.svipe_id,
        )
        self._verify_user_parameters(
            eppn, identity_verified=True, num_proofings=1, num_mfa_tokens=0, locked_identity=new_locked_identity
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_foreign_identity_replace_locked_identity_fail(self, mock_request_user_sync: MagicMock):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.unverified_test_user.eppn
        country = countries.get("Denmark")

        userinfo = self.get_mock_userinfo(issuing_country=country, nationality=country)

        # add a locked svipe identity that will NOT match the new identity
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        user.locked_identity.add(
            SvipeIdentity(
                administrative_number=userinfo.document_administrative_number,
                country_code=userinfo.document_nationality,
                date_of_birth=datetime.today(),  # not matching the new identity
                is_verified=True,
                svipe_id="another_svipe_id",
            )
        )
        self.app.central_userdb.save(user)

        with self.app.test_request_context():
            endpoint = url_for("svipe_id.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country, nationality=country)
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
            eppn, identity_verified=False, num_proofings=0, num_mfa_tokens=0, locked_identity=user.locked_identity.svipe
        )

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_foreign_identity_replace_locked_identity_fail_admin_number(self, mock_request_user_sync: MagicMock):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.unverified_test_user.eppn
        country = countries.get("Denmark")
        admin_number = "1234567890"
        other_admin_number = "0987654321"

        userinfo = self.get_mock_userinfo(
            issuing_country=country, nationality=country, administrative_number=admin_number
        )

        # add a locked svipe identity that will NOT match the new identity
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        user.locked_identity.add(
            SvipeIdentity(
                administrative_number=other_admin_number,  # not matching the new identity
                country_code=userinfo.document_nationality,
                date_of_birth=datetime.combine(userinfo.birthdate.today(), datetime.min.time()),
                is_verified=True,
                svipe_id="another_svipe_id",
            )
        )
        self.app.central_userdb.save(user)

        with self.app.test_request_context():
            endpoint = url_for("svipe_id.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country, nationality=country)
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
            eppn, identity_verified=False, num_proofings=0, num_mfa_tokens=0, locked_identity=user.locked_identity.svipe
        )

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_foreign_identity_already_verified_nin(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock
    ):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user.eppn
        country = countries.get("Denmark")

        with self.app.test_request_context():
            endpoint = url_for("svipe_id.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        userinfo = self.get_mock_userinfo(issuing_country=country, nationality=country)
        response = self.mock_authorization_callback(state=state, nonce=nonce, userinfo=userinfo)
        assert response.status_code == 302
        self._verify_status(
            finish_url=response.headers["Location"],
            frontend_action=FrontendAction(self.default_frontend_data["frontend_action"]),
            frontend_state=self.default_frontend_data["frontend_state"],
            method=self.default_frontend_data["method"],
            expect_msg=SvipeIDMsg.identity_verify_success,
        )
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        self._verify_user_parameters(
            eppn, identity_verified=True, num_proofings=1, num_mfa_tokens=0, locked_identity=user.identities.svipe
        )
        self._verify_user_parameters(
            eppn, identity_verified=True, num_proofings=1, num_mfa_tokens=0, locked_identity=user.identities.nin
        )

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_verify_identity_expired_document(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock
    ):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.unverified_test_user.eppn
        country = countries.get("Sweden")

        with self.app.test_request_context():
            endpoint = url_for("svipe_id.verify_identity")

        start_auth_response = self._start_auth(endpoint=endpoint, data=self.default_frontend_data, eppn=eppn)
        state, nonce = self._get_state_and_nonce(self.get_response_payload(start_auth_response)["location"])
        yesterday = utc_now() - timedelta(days=1)
        userinfo = self.get_mock_userinfo(issuing_country=country, nationality=country, document_expires=yesterday)
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
