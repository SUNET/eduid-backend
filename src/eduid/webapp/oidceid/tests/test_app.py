import datetime
import json
import logging
import time
import uuid
from http import HTTPStatus
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pygrindvakt import jwt, keys
from pygrindvakt.keys import SigningKey
from pygrindvakt.metadata import ProviderMetadata
from pytest_mock import MockerFixture
from werkzeug.test import TestResponse

from eduid.common.clients.oidc_client.base import OidcRpClient, OidcRpError
from eduid.common.clients.oidc_client.grindvakt_client import GrindvaktOidcRpClient
from eduid.common.clients.oidc_client.testing import FakeOidcRpClient, StaticHttpClient
from eduid.common.config.base import EduidEnvironment, FrontendAction
from eduid.userdb import NinIdentity
from eduid.userdb.credentials.external import (
    EidasCredential,
    ExternalCredential,
    SwedenConnectCredential,
    TrustFramework,
)
from eduid.userdb.element import ElementKey
from eduid.userdb.identity import EIDASIdentity, EIDASLoa, IdentityProofingMethod, PridPersistence
from eduid.webapp.common.api.messages import AuthnStatusMsg, CommonMsg, TranslatableMsg
from eduid.webapp.common.api.testing import CSRFTestClient
from eduid.webapp.common.api.utils import get_external_url
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.common.proofing.methods import ProofingMethods
from eduid.webapp.common.proofing.testing import ProofingTests
from eduid.webapp.common.session.namespaces import (
    ExternalMfaSignupEIDASIdentity,
    ExternalMfaSignupSwedenConnectIdentity,
    OIDCState,
)
from eduid.webapp.oidceid import claims as oidc_claims
from eduid.webapp.oidceid.app import OidcEidApp, init_oidceid_app
from eduid.webapp.oidceid.helpers import OidcEidMsg
from eduid.webapp.oidceid.settings.common import SwedenConnectOidcClientConfig

__author__ = "lundberg"

logger = logging.getLogger(__name__)

# Two OpenID Providers: freja goes to A, eIDAS goes to B, the magic cookie swaps them
OP_A = "https://op-a.example.com/oidc"
OP_B = "https://op-b.example.com/oidc"
CLIENT_ID = "test_client_id"
EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)

LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3"
LOA2 = "http://id.elegnamnden.se/loa/1.0/loa2"
EIDAS_NF_SUB = "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub"
EIDAS_NF_LOW = "http://id.elegnamnden.se/loa/1.0/eidas-nf-low"

FREJA = "freja"
EIDAS = "eidas"


class OidcEidTests(ProofingTests[OidcEidApp]):
    """Base TestCase for those tests that need a full environment setup"""

    api_users: ClassVar[list[str]] = ["hubba-bubba", "hubba-baar"]

    @pytest.fixture(autouse=True)
    def setup(self, setup_api: None) -> None:
        self.test_user_eppn = "hubba-bubba"
        self.test_unverified_user_eppn = "hubba-baar"
        self.test_user_nin = NinIdentity(
            number="197801011234",
            date_of_birth=datetime.datetime.fromisoformat("1978-01-01").replace(tzinfo=datetime.UTC),
        )
        self.test_user_eidas = EIDASIdentity(
            prid="XB:1bjrk7depnmhu7xn56kon3mlc9q1s0",
            prid_persistence=PridPersistence.B,
            loa=EIDASLoa.NF_SUBSTANTIAL,
            date_of_birth=datetime.datetime.fromisoformat("1964-12-31").replace(tzinfo=datetime.UTC),
            country_code="XB",
        )
        self.test_user_wrong_nin = NinIdentity(
            number="190001021234",
            date_of_birth=datetime.datetime.fromisoformat("1900-01-02").replace(tzinfo=datetime.UTC),
        )
        self.test_user_other_eidas = EIDASIdentity(
            prid="XA:some_other_prid",
            prid_persistence=PridPersistence.B,
            loa=EIDASLoa.NF_SUBSTANTIAL,
            date_of_birth=datetime.datetime.fromisoformat("1920-11-18").replace(tzinfo=datetime.UTC),
            country_code="XA",
        )
        self.test_backdoor_nin = NinIdentity(
            number="190102031234",
            date_of_birth=datetime.datetime.fromisoformat("1901-02-03").replace(tzinfo=datetime.UTC),
        )
        # The apps clients are restored after each test by setup_api
        self.fakes: dict[str, FakeOidcRpClient] = {}
        for issuer in (OP_A, OP_B):
            self.fakes[issuer] = FakeOidcRpClient(authorization_endpoint=f"{issuer}/authorize", issuer=issuer)
            self.app.oidc_clients[issuer] = self.fakes[issuer]

    @classmethod
    def load_app(cls, config: dict[str, Any]) -> OidcEidApp:
        return init_oidceid_app("testing", config)

    @pytest.fixture(scope="class")
    @classmethod
    def update_config(cls) -> dict[str, Any]:
        config = cls._get_base_config()
        # pygrindvakt only accepts https redirect URIs for non-loopback hosts
        config["preferred_url_scheme"] = "https"
        config.update(
            {
                "providers": [
                    {
                        "client_id": CLIENT_ID,
                        "client_secret": "test_client_secret",
                        "token_endpoint_auth_method": "client_secret_basic",
                        # signed userinfo is required whenever fetch_userinfo is enabled
                        "userinfo_trust": "typed",
                        "userinfo_typ": "userinfo+jwt",
                        "issuer": issuer,
                    }
                    for issuer in (OP_A, OP_B)
                ],
                "safe_relay_domain": "localhost",
                "magic_cookie": "",
                "magic_cookie_name": "magic-cookie",
                # the magic cookie sends the user to the other OP, to be able to see it is used
                "magic_cookie_idp": OP_B,
                "magic_cookie_bankid_idp": OP_B,
                "magic_cookie_foreign_id_idp": OP_A,
                "environment": "dev",
                "freja_idp": OP_A,
                "foreign_identity_idp": OP_B,
                "errors_url_template": "http://localhost/errors?code={ERRORURL_CODE}&ts={ERRORURL_TS}&rp={ERRORURL_RP}"
                "&tid={ERRORURL_TID}&ctx={ERRORURL_CTX}",
                "frontend_action_authn_parameters": {
                    FrontendAction.LOGIN_MFA_AUTHN.value: {
                        "force_authn": True,
                        "force_mfa": True,
                        "finish_url": "http://test.localhost/testing-mfa-authenticate/{app_name}/{authn_id}",
                    },
                    FrontendAction.VERIFY_IDENTITY.value: {
                        "force_authn": True,
                        "finish_url": "http://test.localhost/testing-verify-identity/{app_name}/{authn_id}",
                    },
                    FrontendAction.VERIFY_CREDENTIAL.value: {
                        "force_authn": True,
                        "force_mfa": True,
                        "allow_login_auth": True,
                        "allow_signup_auth": True,
                        "finish_url": "http://test.localhost/testing-verify-credential/{app_name}/{authn_id}",
                    },
                    FrontendAction.SIGNUP_EXTERNAL_MFA.value: {
                        "force_authn": True,
                        "force_mfa": True,
                        "same_user": False,
                        "allow_signup_auth": True,
                        "finish_url": "http://test.localhost/testing-mfa-register/{app_name}/{authn_id}",
                    },
                },
            }
        )
        return config

    # ---- test data -----------------------------------------------------------------------------------------

    def add_nin_to_user(self, eppn: str, nin: str, verified: bool) -> NinIdentity:
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        nin_element = NinIdentity(number=nin, created_by="test", is_verified=verified)
        user.identities.add(nin_element)
        self.request_user_sync(user)
        return nin_element

    def set_eidas_for_user(self, eppn: str, identity: EIDASIdentity, verified: bool) -> None:
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        identity.is_verified = verified
        user.identities.replace(element=identity)
        if verified is True:
            user.locked_identity.replace(element=identity)
        self.request_user_sync(user)

    @staticmethod
    def build_claims(
        method: str,
        identity: NinIdentity | EIDASIdentity,
        issuer: str,
        *,
        age: int = 10,
        acr: str | None = None,
        drop: tuple[str, ...] = (),
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """The ID token claims a Sweden Connect OP would return for the identity."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": issuer,
            "sub": "subject-1",
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 300,
            "auth_time": now - age,
            oidc_claims.CLAIM_BIRTHDATE: (identity.date_of_birth or EPOCH).strftime("%Y-%m-%d"),
        }
        if method == FREJA:
            claims.update(
                {
                    "acr": acr or LOA3,
                    oidc_claims.CLAIM_PERSONAL_IDENTITY_NUMBER: identity.unique_value,
                    oidc_claims.CLAIM_GIVEN_NAME: "Ûlla",
                    oidc_claims.CLAIM_FAMILY_NAME: "Älm",
                    oidc_claims.CLAIM_NAME: "Ülla Älm",
                }
            )
        elif method == EIDAS:
            assert isinstance(identity, EIDASIdentity)
            claims.update(
                {
                    "acr": acr or EIDAS_NF_SUB,
                    oidc_claims.CLAIM_PRID: identity.unique_value,
                    oidc_claims.CLAIM_PRID_PERSISTENCE: identity.prid_persistence.value,
                    oidc_claims.CLAIM_EIDAS_PERSON_IDENTIFIER: "XB/SE/ZWRlbiBSb290IENlcnRpZmljYXRpb24g",
                    oidc_claims.CLAIM_EIDAS_COUNTRY: identity.country_code,
                    oidc_claims.CLAIM_TXN: "_AbZv3Bk5c4d5n0LhvlXqaoTAQCJywBbOBx8Vf58gHL9uroDL7Jfez2tLxqIegCT",
                    oidc_claims.CLAIM_GIVEN_NAME: "Javier",
                    oidc_claims.CLAIM_FAMILY_NAME: "Garcia",
                }
            )
        else:
            raise ValueError(method)
        claims.update(extra or {})
        for name in drop:
            claims.pop(name, None)
        return claims

    # ---- driving the app -----------------------------------------------------------------------------------

    @staticmethod
    def _verify_finish_url(finish_url: str, expected_finish_url: str) -> None:
        # Remove the /{app_name}/{authn_id} part from the finish URL
        finish_url = "/".join(finish_url.split("/")[:-2])
        expected_finish_url = "/".join(expected_finish_url.split("/")[:-2])
        assert finish_url == expected_finish_url, f"expected finish url {expected_finish_url} but got {finish_url}"

    def _start(
        self,
        browser: CSRFTestClient,
        endpoint: str,
        method: str,
        frontend_action: FrontendAction,
        expect_success: bool = True,
        verify_credential: ElementKey | None = None,
        frontend_state: str | None = None,
    ) -> str | None:
        """Start an authn with the app, a new state and nonce is handed out by the fake clients."""
        for fake in self.fakes.values():
            fake.state = str(uuid.uuid4())
            fake.nonce = str(uuid.uuid4())
        with browser.session_transaction() as sess:
            csrf_token = sess.get_csrf_token()
        req = {"csrf_token": csrf_token, "method": method, "frontend_action": frontend_action.value}
        if frontend_state:
            req["frontend_state"] = frontend_state
        if endpoint == "/verify-credential" and verify_credential:
            req["credential_id"] = verify_credential
        response = browser.post(endpoint, json=req)
        if expect_success:
            self._check_success_response(response, type_=None, payload={"csrf_token": csrf_token})
            loc = self.get_response_payload(response).get("location")
            assert loc is not None
            return str(loc)
        payload = {"csrf_token": csrf_token}
        if verify_credential:
            payload["credential_description"] = "unit test webauthn token"
        self._check_error_response(response, type_=None, payload=payload, msg=AuthnStatusMsg.must_authenticate)
        return None

    @staticmethod
    def _pending_authn(browser: CSRFTestClient) -> tuple[str, str]:
        """The state and OP issuer of the one pending authn request in the session"""
        with browser.session_transaction() as sess:
            authns = sess.oidceid.rp.authns
            assert len(authns) == 1, "More or less than one authn request in the session"
            authn = next(iter(authns.values()))
            return str(authn.authn_id), authn.oidc_issuer

    def _callback(
        self,
        browser: CSRFTestClient,
        state: str,
        claims: dict[str, Any] | None = None,
        query: str | None = None,
        issuer: str | None = None,
    ) -> TestResponse:
        """Do the redirect back from the OP, with the fake client of the OP returning the claims."""
        if claims is not None:
            for fake in self.fakes.values():
                fake.claims = claims
                fake.tokens = {"access_token": "access_token", "token_type": "Bearer", "id_token": "id_token"}
                fake.userinfo_response = {}
        if query is None:
            query = f"state={state}&code=mock_code"
            if issuer:
                query += f"&iss={issuer}"
        return browser.get(f"/authn-callback?{query}")

    def _run(
        self,
        endpoint: str,
        method: str,
        expect_msg: TranslatableMsg,
        frontend_action: FrontendAction,
        eppn: str | None = None,
        identity: NinIdentity | EIDASIdentity | None = None,
        age: int = 10,
        acr: str | None = None,
        drop: tuple[str, ...] = (),
        browser: CSRFTestClient | None = None,
        credentials_used: list[ElementKey] | None = None,
        expect_error: bool = False,
        logged_in: bool = True,
        verify_credential: ElementKey | None = None,
        frontend_state: str | None = "This is a unit test",
    ) -> None:
        """Start an authn, return from the OP with matching claims and verify the result in /get-status."""
        if eppn is None:
            eppn = self.test_user_eppn
        if identity is None:
            identity = self.test_user_nin if method == FREJA else self.test_user_eidas
        if browser is None:
            browser = self.browser
        assert isinstance(browser, CSRFTestClient)

        expected_finish_url = self.app.conf.frontend_action_authn_parameters[frontend_action].finish_url

        if logged_in:
            browser_with_session_cookie = self.session_cookie(browser, eppn)
            self.set_authn_action(eppn=eppn, frontend_action=FrontendAction.LOGIN, credentials_used=credentials_used)
        else:
            browser_with_session_cookie = self.session_cookie_anon(browser)

        with browser_with_session_cookie as browser:
            with browser.session_transaction() as sess:
                if logged_in is False:
                    # the user is at least partially logged in at this stage
                    sess.common.eppn = eppn
                if frontend_action is FrontendAction.LOGIN_MFA_AUTHN:
                    sess.mfa_action.login_ref = "test login ref"
                    sess.mfa_action.eppn = eppn

            self._start(
                browser=browser,
                endpoint=endpoint,
                method=method,
                frontend_action=frontend_action,
                verify_credential=verify_credential,
                frontend_state=frontend_state,
            )
            state, issuer = self._pending_authn(browser)
            claims = self.build_claims(method, identity, issuer, age=age, acr=acr, drop=drop)
            response = self._callback(browser, state, claims)

            assert response.status_code == HTTPStatus.FOUND
            self._verify_finish_url(finish_url=response.location, expected_finish_url=expected_finish_url)
            self._verify_status(
                browser=browser,
                expect_msg=expect_msg,
                expect_error=expect_error,
                finish_url=response.location,
                frontend_action=frontend_action,
                frontend_state=frontend_state,
                method=method,
            )

    def reauthn(
        self, endpoint: str, expect_msg: TranslatableMsg, frontend_action: FrontendAction, **kwargs: Any
    ) -> None:
        method = kwargs.pop("method")
        self._run(endpoint, method, expect_msg, frontend_action, **kwargs)

    def verify_token(
        self, endpoint: str, expect_msg: TranslatableMsg, frontend_action: FrontendAction, **kwargs: Any
    ) -> None:
        method = kwargs.pop("method")
        self._run(endpoint, method, expect_msg, frontend_action, **kwargs)

    def _post_anon(self, endpoint: str, req: dict[str, Any], eppn: str | None = None) -> TestResponse:
        with self.session_cookie(self.browser, eppn) if eppn else self.session_cookie_anon(self.browser) as browser:
            with browser.session_transaction() as sess:
                req["csrf_token"] = sess.get_csrf_token()
            return browser.post(endpoint, json=req)


class NINMethodTests(OidcEidTests):
    """Tests for the freja method, used for NIN verification"""

    def test_authenticate(self) -> None:
        response = self.browser.get("/")
        assert response.status_code == 401
        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            response = browser.get("/")
        self._check_success_response(response, type_="GET_OIDCEID_SUCCESS")

    def test_u2f_token_verify(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(eppn, "test", "u2f")
        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint="/verify-credential",
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
            eppn=eppn,
            expect_msg=OidcEidMsg.credential_verify_success,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            method=FREJA,
        )

        self._verify_user_parameters(eppn, token_verified=True, num_proofings=1)

    def test_webauthn_token_verify(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")
        self._verify_user_parameters(eppn)

        self.verify_token(
            endpoint="/verify-credential",
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
            eppn=eppn,
            expect_msg=OidcEidMsg.credential_verify_success,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            method=FREJA,
        )

        self._verify_user_parameters(eppn, token_verified=True, num_proofings=1)

    def test_webauthn_token_verify_signup_authn(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")
        self.setup_signup_authn(eppn=eppn)

        self.verify_token(
            endpoint="/verify-credential",
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
            eppn=eppn,
            expect_msg=OidcEidMsg.credential_verify_success,
            verify_credential=credential.key,
            logged_in=False,
            method=FREJA,
        )

        self._verify_user_parameters(eppn, token_verified=True, num_proofings=1)

    def test_webauthn_token_verify_signup_authn_token_to_old(self) -> None:
        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(
            eppn=eppn,
            keyhandle="test",
            token_type="webauthn",
            created_ts=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=6),
        )
        self.setup_signup_authn(eppn=eppn)

        with self.session_cookie(self.browser, eppn) as browser:
            location = self._start(
                browser=browser,
                endpoint="/verify-credential",
                method=FREJA,
                frontend_action=FrontendAction.VERIFY_CREDENTIAL,
                verify_credential=credential.key,
                expect_success=False,
            )
            assert location is None

        self._verify_user_parameters(eppn, token_verified=False, num_proofings=0)

    def test_mfa_token_verify_wrong_verified_nin(self) -> None:
        eppn = self.test_user.eppn
        nin = self.test_user_wrong_nin
        credential = self.add_security_key_to_user(eppn, "test", "u2f")

        self.verify_token(
            endpoint="/verify-credential",
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
            eppn=eppn,
            expect_msg=OidcEidMsg.identity_not_matching,
            expect_error=True,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            identity=nin,
            method=FREJA,
        )

        self._verify_user_parameters(eppn, identity=nin, identity_present=False)

    def test_mfa_token_verify_no_verified_nin(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")
        self._verify_user_parameters(eppn, identity_verified=False)

        self.verify_token(
            endpoint="/verify-credential",
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
            eppn=eppn,
            expect_msg=OidcEidMsg.credential_verify_success,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            identity=self.test_user_nin,
            method=FREJA,
        )

        # Verify the user now has a verified NIN
        self._verify_user_parameters(
            eppn,
            token_verified=True,
            num_proofings=2,
            identity_present=True,
            identity=self.test_user_nin,
            identity_verified=True,
        )

    def test_mfa_token_verify_no_mfa_login(self) -> None:
        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(eppn, "test", "u2f")

        with self.session_cookie(self.browser, eppn) as browser:
            with browser.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            req = {
                "credential_id": credential.key,
                "method": FREJA,
                "frontend_action": FrontendAction.VERIFY_CREDENTIAL.value,
                "csrf_token": csrf_token,
            }
            response = browser.post("/verify-credential", json=req)

        self._check_error_response(
            response=response,
            type_="POST_OIDCEID_VERIFY_CREDENTIAL_FAIL",
            msg=AuthnStatusMsg.must_authenticate,
            payload={"credential_description": "unit test U2F token"},
        )
        self._verify_user_parameters(eppn)

    def test_webauthn_token_verify_backdoor(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        nin = self.test_backdoor_nin
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        self.app.conf.magic_cookie = "magic-cookie"
        with self.session_cookie_and_magic_cookie(self.browser, eppn=eppn) as browser:
            browser.set_cookie(domain=self.test_domain, key="nin", value=nin.number)
            self.verify_token(
                endpoint="/verify-credential",
                eppn=eppn,
                frontend_action=FrontendAction.VERIFY_CREDENTIAL,
                method=FREJA,
                expect_msg=OidcEidMsg.credential_verify_success,
                credentials_used=[credential.key, ElementKey("other_id")],
                verify_credential=credential.key,
                browser=browser,
            )

        self._verify_user_parameters(eppn, identity=nin, identity_verified=True, token_verified=True, num_proofings=2)

    def test_nin_verify(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False)

        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            method=FREJA,
            expect_msg=OidcEidMsg.identity_verify_success,
            eppn=eppn,
        )
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        self._verify_user_parameters(
            eppn,
            num_mfa_tokens=0,
            identity_verified=True,
            num_proofings=1,
            locked_identity=user.identities.nin,
            proofing_method=IdentityProofingMethod.SWEDEN_CONNECT,
            proofing_version=self.app.conf.freja_proofing_version,
        )
        assert user.given_name == "Ûlla"
        assert user.surname == "Älm"
        doc = self.app.proofing_log._get_documents_by_attr(attr="eduPersonPrincipalName", value=eppn)[0]
        assert doc["given_name"] == "Ûlla"
        assert doc["surname"] == "Älm"

    def test_nin_verify_signup_auth(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        self.setup_signup_authn(eppn=eppn)

        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            method=FREJA,
            expect_msg=OidcEidMsg.identity_verify_success,
            eppn=eppn,
            logged_in=False,
        )
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=True, num_proofings=1)

    def test_nin_verify_already_verified(self) -> None:
        eppn = self.test_user.eppn
        nin = self.test_user_nin
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=nin, identity_verified=True)

        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            method=FREJA,
            expect_msg=ProofingMsg.identity_already_verified,
            expect_error=True,
            identity=nin,
        )

    def test_nin_verify_locked_nin_mismatch(self, mocker: MockerFixture) -> None:
        """A user with a locked NIN can not verify another NIN"""
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        user.locked_identity.add(
            NinIdentity(created_by="test", number=self.test_user_wrong_nin.number, is_verified=True)
        )
        self.app.central_userdb.save(user)

        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            method=FREJA,
            expect_msg=CommonMsg.locked_identity_not_matching,
            expect_error=True,
            eppn=eppn,
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False, num_proofings=0)

    def test_mfa_login(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_user.eppn
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user.credentials.filter(SwedenConnectCredential) == []
        credentials_before = user.credentials.to_list()

        self.reauthn(
            "/mfa-authenticate",
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
            method=FREJA,
            expect_msg=OidcEidMsg.mfa_authn_success,
            eppn=eppn,
            logged_in=False,
        )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=True, num_proofings=0)
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert len(user.credentials.to_list()) == len(credentials_before) + 1
        creds = user.credentials.filter(SwedenConnectCredential)
        assert len(creds) == 1
        assert creds[0].level in self.app.conf.required_loa

    def test_mfa_login_no_nin(self) -> None:
        eppn = self.test_unverified_user_eppn
        self.reauthn(
            "/mfa-authenticate",
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
            method=FREJA,
            expect_msg=OidcEidMsg.identity_not_matching,
            expect_error=True,
            eppn=eppn,
            logged_in=False,
        )
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False, num_proofings=0)

    def test_mfa_login_unverified_nin(self, mocker: MockerFixture) -> None:
        """A user with a locked NIN, but no verified identity, gets the identity verified when logging in"""
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        user.locked_identity.add(NinIdentity(created_by="test", number=self.test_user_nin.number, is_verified=True))
        self.app.central_userdb.save(user)

        self.reauthn(
            "/mfa-authenticate",
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
            method=FREJA,
            expect_msg=OidcEidMsg.mfa_authn_success,
            eppn=eppn,
            logged_in=False,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, identity_verified=True, num_proofings=1, locked_identity=user.identities.nin
        )

    def test_mfa_login_backdoor(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        nin = self.test_backdoor_nin
        self.add_nin_to_user(eppn=eppn, nin=nin.number, verified=True)
        self.app.conf.magic_cookie = "magic-cookie"

        with self.session_cookie(self.browser, eppn) as browser:
            browser.set_cookie(domain="test.localhost", key="magic-cookie", value=self.app.conf.magic_cookie)
            browser.set_cookie(domain="test.localhost", key="nin", value=nin.number)
            self.reauthn(
                "/mfa-authenticate",
                frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
                method=FREJA,
                expect_msg=OidcEidMsg.mfa_authn_success,
                eppn=eppn,
                logged_in=False,
                browser=browser,
            )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=nin, identity_verified=True, num_proofings=0)

    def test_nin_verify_backdoor(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        nin = self.test_backdoor_nin
        self.app.conf.magic_cookie = "magic-cookie"

        with self.session_cookie_and_magic_cookie(self.browser, eppn) as browser:
            browser.set_cookie(domain="test.localhost", key="nin", value=nin.number)
            self.reauthn(
                "/verify-identity",
                frontend_action=FrontendAction.VERIFY_IDENTITY,
                method=FREJA,
                expect_msg=OidcEidMsg.identity_verify_success,
                eppn=eppn,
                browser=browser,
            )

        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity=nin, identity_verified=True, num_proofings=1)

    def test_nin_verify_no_backdoor_in_pro(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.environment = EduidEnvironment.production

        with self.session_cookie_and_magic_cookie(self.browser, eppn=eppn) as browser:
            browser.set_cookie(domain=self.test_domain, key="nin", value=self.test_backdoor_nin.number)
            self.reauthn(
                "/verify-identity",
                frontend_action=FrontendAction.VERIFY_IDENTITY,
                method=FREJA,
                expect_msg=OidcEidMsg.identity_verify_success,
                eppn=eppn,
                browser=browser,
            )

        # the default nin was verified and not the nin set in the test cookie
        self._verify_user_parameters(
            eppn, identity=self.test_user_nin, num_mfa_tokens=0, num_proofings=1, identity_verified=True
        )

    def test_nin_verify_no_backdoor_misconfigured(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        self.app.conf.magic_cookie = "magic-cookie"

        with self.session_cookie_and_magic_cookie(
            self.browser, eppn=eppn, magic_cookie_value="NOT-the-magic-cookie"
        ) as browser:
            browser.set_cookie(domain="test.localhost", key="nin", value=self.test_backdoor_nin.number)
            self.reauthn(
                "/verify-identity",
                frontend_action=FrontendAction.VERIFY_IDENTITY,
                method=FREJA,
                expect_msg=OidcEidMsg.identity_verify_success,
                eppn=eppn,
                browser=browser,
            )

        self._verify_user_parameters(
            eppn, identity=self.test_user_nin, num_mfa_tokens=0, num_proofings=1, identity_verified=True
        )

    def test_mfa_authentication_too_old_authn_instant(self) -> None:
        self.reauthn(
            endpoint="/mfa-authenticate",
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
            method=FREJA,
            age=61,
            expect_msg=OidcEidMsg.authn_instant_too_old,
            expect_error=True,
        )

    def test_mfa_authentication_wrong_nin(self) -> None:
        self.reauthn(
            endpoint="/mfa-authenticate",
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
            method=FREJA,
            expect_msg=OidcEidMsg.identity_not_matching,
            expect_error=True,
            identity=self.test_user_wrong_nin,
        )

    def test_nin_staging_remap_verify(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        remapped_nin = NinIdentity(number="190102031234")
        self.app.conf.environment = EduidEnvironment.staging
        self.app.conf.nin_attribute_map = {self.test_user_nin.number: remapped_nin.number}

        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            method=FREJA,
            expect_msg=OidcEidMsg.identity_verify_success,
            eppn=eppn,
            identity=self.test_user_nin,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, identity=remapped_nin, identity_verified=True, num_proofings=1
        )

    def test_verify_credential_stale_reauthn(self) -> None:
        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        self.verify_token(
            endpoint="/verify-credential",
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
            eppn=eppn,
            expect_msg=OidcEidMsg.identity_not_matching,
            expect_error=True,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            identity=self.test_user_wrong_nin,
            method=FREJA,
        )

    def test_verify_credential_eidas_not_allowed(self) -> None:
        """verify-credential with method=eidas is rejected when allow_eidas_credential_verification=False"""
        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")
        assert self.app.conf.allow_eidas_credential_verification is False

        response = self._post_anon(
            "/verify-credential",
            {
                "credential_id": credential.key,
                "method": EIDAS,
                "frontend_action": FrontendAction.VERIFY_CREDENTIAL.value,
            },
            eppn=eppn,
        )

        self._check_error_response(
            response=response,
            type_="POST_OIDCEID_VERIFY_CREDENTIAL_FAIL",
            msg=OidcEidMsg.credential_verification_not_allowed,
        )
        self._verify_user_parameters(eppn)

    def test_verify_credential_invalid_frontend_action(self) -> None:
        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")
        response = self._post_anon(
            "/verify-credential",
            {
                "credential_id": credential.key,
                "method": FREJA,
                "frontend_action": FrontendAction.VERIFY_IDENTITY.value,
            },
            eppn=eppn,
        )
        self._check_error_response(
            response=response,
            type_="POST_OIDCEID_VERIFY_CREDENTIAL_FAIL",
            msg=OidcEidMsg.frontend_action_not_supported,
        )

    def test_verify_credential_missing_credential(self) -> None:
        response = self._post_anon(
            "/verify-credential",
            {
                "credential_id": "non_existent_credential_id",
                "method": FREJA,
                "frontend_action": FrontendAction.VERIFY_CREDENTIAL.value,
            },
            eppn=self.test_user.eppn,
        )
        self._check_error_response(
            response=response, type_="POST_OIDCEID_VERIFY_CREDENTIAL_FAIL", msg=OidcEidMsg.credential_not_found
        )

    def test_authn_unsupported_frontend_action(self) -> None:
        response = self._post_anon(
            "/verify-identity",
            {"method": FREJA, "frontend_action": FrontendAction.CHANGE_PW_AUTHN.value},
            eppn=self.test_user.eppn,
        )
        self._check_error_response(
            response=response, type_="POST_OIDCEID_VERIFY_IDENTITY_FAIL", msg=OidcEidMsg.frontend_action_not_supported
        )

    def test_authn_method_not_available(self) -> None:
        self.app.conf.freja_idp = None
        response = self._post_anon(
            "/verify-identity",
            {"method": FREJA, "frontend_action": FrontendAction.VERIFY_IDENTITY.value},
            eppn=self.test_user.eppn,
        )
        self._check_error_response(
            response=response, type_="POST_OIDCEID_VERIFY_IDENTITY_FAIL", msg=OidcEidMsg.method_not_available
        )

    def test_authn_unsupported_method(self) -> None:
        """bankid is not yet supported by the OPs"""
        self.app.conf.bankid_idp = OP_A
        response = self._post_anon(
            "/verify-identity",
            {"method": "bankid", "frontend_action": FrontendAction.VERIFY_IDENTITY.value},
            eppn=self.test_user.eppn,
        )
        self._check_error_response(
            response=response, type_="POST_OIDCEID_VERIFY_IDENTITY_FAIL", msg=OidcEidMsg.method_not_available
        )

    def test_authn_no_client_for_idp(self) -> None:
        del self.app.oidc_clients[OP_A]
        response = self._post_anon(
            "/verify-identity",
            {"method": FREJA, "frontend_action": FrontendAction.VERIFY_IDENTITY.value},
            eppn=self.test_user.eppn,
        )
        self._check_error_response(
            response=response, type_="POST_OIDCEID_VERIFY_IDENTITY_FAIL", msg=OidcEidMsg.method_not_available
        )

    def test_authn_request_failed(self) -> None:
        self.fakes[OP_A].raise_on_mint = OidcRpError("discovery failed")
        response = self._post_anon(
            "/verify-identity",
            {"method": FREJA, "frontend_action": FrontendAction.VERIFY_IDENTITY.value},
            eppn=self.test_user.eppn,
        )
        self._check_error_response(
            response=response, type_="POST_OIDCEID_VERIFY_IDENTITY_FAIL", msg=OidcEidMsg.authn_request_failed
        )

    def test_magic_cookie_swaps_op(self) -> None:
        """With the magic cookie the freja method is sent to the magic cookie OP"""
        eppn = self.test_user.eppn
        self.app.conf.magic_cookie = "magic-cookie"
        with self.session_cookie_and_magic_cookie(self.browser, eppn=eppn) as browser:
            url = self._start(browser, "/verify-identity", FREJA, FrontendAction.VERIFY_IDENTITY)
            assert url is not None
            assert url.startswith(f"{OP_B}/authorize")
            _state, issuer = self._pending_authn(browser)
            assert issuer == OP_B

    def test_magic_cookie_eidas_method(self) -> None:
        eppn = self.test_user.eppn
        self.app.conf.magic_cookie = "magic-cookie"
        with self.session_cookie_and_magic_cookie(self.browser, eppn=eppn) as browser:
            url = self._start(browser, "/verify-identity", EIDAS, FrontendAction.VERIFY_IDENTITY)
            assert url is not None
            assert url.startswith(f"{OP_A}/authorize")

    def test_magic_cookie_eidas_foreign_id_idp_missing(self) -> None:
        eppn = self.test_user.eppn
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_foreign_id_idp = None
        with self.session_cookie_and_magic_cookie(self.browser, eppn=eppn) as browser:
            with browser.session_transaction() as sess:
                sess.mfa_action.login_ref = "test login ref"
                sess.mfa_action.eppn = eppn
                csrf_token = sess.get_csrf_token()
            response = browser.post(
                "/mfa-authenticate",
                json={"csrf_token": csrf_token, "method": EIDAS, "frontend_action": "loginMfaAuthn"},
            )
        self._check_error_response(
            response=response, type_="POST_OIDCEID_MFA_AUTHENTICATE_FAIL", msg=OidcEidMsg.method_not_available
        )

    def test_magic_cookie_missing_config(self) -> None:
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_idp = None
        with self.session_cookie_and_magic_cookie(self.browser, eppn=self.test_user.eppn) as browser:
            with browser.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            response = browser.post(
                "/verify-identity",
                json={
                    "csrf_token": csrf_token,
                    "method": FREJA,
                    "frontend_action": FrontendAction.VERIFY_IDENTITY.value,
                },
            )
        self._check_error_response(response=response, type_=None, msg=OidcEidMsg.method_not_available)

    def test_get_status_not_found(self) -> None:
        response = self._post_anon("/get-status", {"authn_id": "nonexistent-authn-id"}, eppn=self.test_user.eppn)
        self._check_error_response(
            response=response, type_="POST_OIDCEID_GET_STATUS_FAIL", msg=AuthnStatusMsg.not_found
        )

    # --- mfa-register ---

    def test_mfa_register_init_ok(self) -> None:
        response = self._post_anon(
            "/mfa-register", {"method": FREJA, "frontend_action": FrontendAction.SIGNUP_EXTERNAL_MFA.value}
        )
        self._check_success_response(response, type_=None)
        loc = self.get_response_payload(response).get("location")
        assert loc is not None
        assert loc.startswith(f"{OP_A}/authorize")

    def test_mfa_register_init_rejects_wrong_action(self) -> None:
        response = self._post_anon(
            "/mfa-register", {"method": FREJA, "frontend_action": FrontendAction.LOGIN_MFA_AUTHN.value}
        )
        assert response.get_json()["payload"]["message"] == OidcEidMsg.frontend_action_not_supported.value

    def test_mfa_register_callback_populates_identity_freja(self) -> None:
        with self.session_cookie_anon(self.browser) as browser:
            self._start(browser, "/mfa-register", FREJA, FrontendAction.SIGNUP_EXTERNAL_MFA)
            with browser.session_transaction() as sess:
                assert sess.common.eppn is None
            state, issuer = self._pending_authn(browser)
            response = self._callback(browser, state, self.build_claims(FREJA, self.test_user_nin, issuer))
            assert response.status_code == HTTPStatus.FOUND

            with browser.session_transaction() as sess:
                # the callback must not log anyone in
                assert sess.common.eppn is None
                authn = sess.oidceid.rp.authns[OIDCState(state)]
                assert authn.status == OidcEidMsg.mfa_authn_success.value
                ident = authn.external_mfa_signup_identity
                assert isinstance(ident, ExternalMfaSignupSwedenConnectIdentity)
                assert ident.given_name == "Ûlla"
                assert ident.surname == "Älm"
                assert ident.nin == self.test_user_nin.number
                assert ident.framework == TrustFramework.SWECONN
                assert ident.loa == "loa3"
                assert ident.issuer == OP_A

    def test_mfa_register_callback_populates_identity_eidas(self) -> None:
        with self.session_cookie_anon(self.browser) as browser:
            self._start(browser, "/mfa-register", EIDAS, FrontendAction.SIGNUP_EXTERNAL_MFA)
            state, issuer = self._pending_authn(browser)
            response = self._callback(browser, state, self.build_claims(EIDAS, self.test_user_eidas, issuer))
            assert response.status_code == HTTPStatus.FOUND

            with browser.session_transaction() as sess:
                assert sess.common.eppn is None
                authn = sess.oidceid.rp.authns[OIDCState(state)]
                ident = authn.external_mfa_signup_identity
                assert isinstance(ident, ExternalMfaSignupEIDASIdentity)
                assert ident.given_name == "Javier"
                assert ident.surname == "Garcia"
                assert ident.prid == self.test_user_eidas.unique_value
                assert ident.prid_persistence == self.test_user_eidas.prid_persistence
                assert ident.country_code == self.test_user_eidas.country_code
                assert ident.date_of_birth == datetime.datetime(1964, 12, 31, tzinfo=datetime.UTC)
                assert ident.framework == TrustFramework.EIDAS
                assert ident.loa == "eidas-nf-sub"


class EidasMethodTests(OidcEidTests):
    """Tests for the eidas method (foreign eID)"""

    def test_foreign_eid_mfa_login(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_user.eppn
        self.set_eidas_for_user(eppn=eppn, identity=self.test_user_eidas, verified=True)
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user.credentials.filter(ExternalCredential) == []
        credentials_before = user.credentials.to_list()

        self.reauthn(
            "/mfa-authenticate",
            expect_msg=OidcEidMsg.mfa_authn_success,
            eppn=eppn,
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
            identity=self.test_user_eidas,
            logged_in=False,
            method=EIDAS,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, identity=self.test_user_eidas, identity_verified=True, num_proofings=0
        )
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert len(user.credentials.to_list()) == len(credentials_before) + 1
        eidas_creds = user.credentials.filter(EidasCredential)
        assert len(eidas_creds) == 1
        assert eidas_creds[0].level in self.app.conf.foreign_required_loa

    def test_foreign_eid_mfa_login_no_identity(self) -> None:
        eppn = self.test_unverified_user_eppn
        self.reauthn(
            "/mfa-authenticate",
            expect_msg=OidcEidMsg.identity_not_matching,
            expect_error=True,
            eppn=eppn,
            logged_in=False,
            method=EIDAS,
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
        )
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False, num_proofings=0)

    def test_foreign_eid_mfa_login_unverified_identity(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        identity = self.test_user_eidas
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        identity.is_verified = True
        user.locked_identity.add(identity)
        self.app.central_userdb.save(user)

        self.reauthn(
            "/mfa-authenticate",
            expect_msg=OidcEidMsg.mfa_authn_success,
            eppn=eppn,
            identity=identity,
            logged_in=False,
            method=EIDAS,
            frontend_action=FrontendAction.LOGIN_MFA_AUTHN,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, identity=identity, identity_present=True, identity_verified=True, num_proofings=1
        )

    def test_foreign_eid_webauthn_token_verify(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        self.app.conf.allow_eidas_credential_verification = True
        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")
        self.set_eidas_for_user(eppn=eppn, identity=self.test_user_eidas, verified=True)

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            identity=self.test_user_eidas,
            expect_msg=OidcEidMsg.credential_verify_success,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            method=EIDAS,
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
        )

        self._verify_user_parameters(
            eppn, identity=self.test_user_eidas, identity_verified=True, token_verified=True, num_proofings=1
        )

    def test_foreign_eid_mfa_token_verify_wrong_verified_identity(self) -> None:
        self.app.conf.allow_eidas_credential_verification = True
        eppn = self.test_user.eppn
        identity = self.test_user_other_eidas
        self.set_eidas_for_user(eppn=eppn, identity=identity, verified=True)
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            identity=self.test_user_eidas,
            expect_msg=OidcEidMsg.identity_not_matching,
            expect_error=True,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            method=EIDAS,
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
        )

        self._verify_user_parameters(
            eppn, identity=identity, identity_present=True, identity_verified=True, num_proofings=0
        )

    def test_foreign_eid_mfa_token_verify_no_verified_identity(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        self.app.conf.allow_eidas_credential_verification = True
        eppn = self.test_unverified_user_eppn
        identity = self.test_user_eidas
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        self.verify_token(
            endpoint="/verify-credential",
            eppn=eppn,
            identity=identity,
            expect_msg=OidcEidMsg.credential_verify_success,
            credentials_used=[credential.key, ElementKey("other_id")],
            verify_credential=credential.key,
            method=EIDAS,
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
        )

        self._verify_user_parameters(
            eppn, token_verified=True, num_proofings=2, identity_present=True, identity=identity, identity_verified=True
        )

    def test_foreign_eid_mfa_token_verify_no_mfa_login(self) -> None:
        self.app.conf.allow_eidas_credential_verification = True
        eppn = self.test_user.eppn
        credential = self.add_security_key_to_user(eppn, "test", "webauthn")

        with self.session_cookie(self.browser, eppn) as browser:
            location = self._start(
                browser=browser,
                endpoint="/verify-credential",
                method=EIDAS,
                frontend_action=FrontendAction.VERIFY_CREDENTIAL,
                verify_credential=credential.key,
                expect_success=False,
            )
            assert location is None
        self._verify_user_parameters(eppn)

    def test_foreign_identity_verify(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        identity = self.test_user_eidas

        self.reauthn(
            "/verify-identity",
            expect_msg=OidcEidMsg.identity_verify_success,
            eppn=eppn,
            identity=identity,
            method=EIDAS,
            frontend_action=FrontendAction.VERIFY_IDENTITY,
        )

        user = self.app.central_userdb.get_user_by_eppn(eppn=eppn)
        self._verify_user_parameters(
            eppn,
            num_mfa_tokens=0,
            identity=identity,
            identity_verified=True,
            num_proofings=1,
            locked_identity=user.identities.eidas,
            proofing_method=IdentityProofingMethod.SWEDEN_CONNECT,
            proofing_version=self.app.conf.foreign_eid_proofing_version,
        )

    def test_foreign_identity_verify_eidas_nf_low(self) -> None:
        eppn = self.test_unverified_user_eppn
        self.reauthn(
            "/verify-identity",
            expect_msg=OidcEidMsg.authn_context_mismatch,
            expect_error=True,
            eppn=eppn,
            identity=self.test_user_eidas,
            method=EIDAS,
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            acr=EIDAS_NF_LOW,
        )
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False, num_proofings=0)

    def test_foreign_identity_verify_existing_prid_persistence_A(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        locked_identity = self.test_user_eidas
        locked_identity.prid_persistence = PridPersistence.A
        locked_identity.is_verified = True
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        user.locked_identity.add(locked_identity)
        self.app.central_userdb.save(user)

        self.reauthn(
            "/verify-identity",
            expect_msg=CommonMsg.locked_identity_not_matching,
            expect_error=True,
            eppn=eppn,
            identity=self.test_user_other_eidas,
            method=EIDAS,
            frontend_action=FrontendAction.VERIFY_IDENTITY,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, locked_identity=locked_identity, identity_verified=False, num_proofings=0
        )

    def test_foreign_identity_verify_existing_prid_persistence_B(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        identity = self.test_user_other_eidas
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        locked_identity = EIDASIdentity(
            prid="XA:some_other_other_prid",
            prid_persistence=PridPersistence.B,
            loa=EIDASLoa.NF_SUBSTANTIAL,
            date_of_birth=datetime.datetime.fromisoformat("1920-11-18").replace(tzinfo=datetime.UTC),
            country_code="XX",
            is_verified=True,
        )
        # same names as the OP asserts
        user.given_name = "Javier"
        user.surname = "Garcia"
        user.locked_identity.add(locked_identity)
        self.app.central_userdb.save(user)

        self.reauthn(
            "/verify-identity",
            expect_msg=OidcEidMsg.identity_verify_success,
            eppn=eppn,
            identity=identity,
            method=EIDAS,
            frontend_action=FrontendAction.VERIFY_CREDENTIAL,
        )

        self._verify_user_parameters(
            eppn, num_mfa_tokens=0, locked_identity=identity, identity=identity, identity_verified=True, num_proofings=1
        )


class CallbackTests(OidcEidTests):
    """The protocol level tests: what is requested from the OP and what is accepted from it"""

    def _verify_identity_start(self, browser: CSRFTestClient, method: str = FREJA) -> tuple[str, str]:
        self._start(browser, "/verify-identity", method, FrontendAction.VERIFY_IDENTITY, frontend_state="state")
        return self._pending_authn(browser)

    def _assert_not_verified(self, eppn: str) -> None:
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=False, num_proofings=0)

    def _status(self, browser: CSRFTestClient, state: str) -> dict[str, Any]:
        with browser.session_transaction() as sess:
            csrf_token = sess.get_csrf_token()
        response = browser.post("/get-status", json={"authn_id": state, "csrf_token": csrf_token})
        payload = self.get_response_payload(response)
        assert isinstance(payload, dict)
        return payload

    # a. / b. LoA and freshness

    def test_acr_below_required_loa(self) -> None:
        eppn = self.test_unverified_user_eppn
        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            method=FREJA,
            expect_msg=OidcEidMsg.authn_context_mismatch,
            expect_error=True,
            eppn=eppn,
            acr=LOA2,
        )
        self._assert_not_verified(eppn)

    def test_unknown_acr(self) -> None:
        eppn = self.test_unverified_user_eppn
        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            method=FREJA,
            expect_msg=OidcEidMsg.authn_context_mismatch,
            expect_error=True,
            eppn=eppn,
            acr="urn:example:something-else",
        )
        self._assert_not_verified(eppn)

    @pytest.mark.parametrize("age", [61, 3600, 86400 * 30])
    def test_old_auth_time(self, age: int) -> None:
        eppn = self.test_unverified_user_eppn
        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            method=FREJA,
            expect_msg=OidcEidMsg.authn_instant_too_old,
            expect_error=True,
            eppn=eppn,
            age=age,
        )
        self._assert_not_verified(eppn)

    # c. mix-up

    def test_iss_of_other_op_rejected(self) -> None:
        eppn = self.test_unverified_user_eppn
        with self.session_cookie(self.browser, eppn) as browser:
            state, issuer = self._verify_identity_start(browser)
            assert issuer == OP_A
            claims = self.build_claims(FREJA, self.test_user_nin, OP_B)
            response = self._callback(browser, state, claims, issuer=OP_B)

            assert response.status_code == HTTPStatus.FOUND
            assert self.fakes[OP_A].finish_calls == []
            assert self.fakes[OP_B].finish_calls == []
            status = self._status(browser, state)
            assert status["error"] is True
            assert status["status"] == OidcEidMsg.authorization_error.value
        self._assert_not_verified(eppn)

    def test_id_token_issuer_of_other_op_rejected(self) -> None:
        """The ID token iss must be the OP the request was sent to, also when the client accepted the token"""
        eppn = self.test_unverified_user_eppn
        with self.session_cookie(self.browser, eppn) as browser:
            state, _issuer = self._verify_identity_start(browser)
            claims = self.build_claims(FREJA, self.test_user_nin, OP_B)
            response = self._callback(browser, state, claims)

            assert response.status_code == HTTPStatus.FOUND
            status = self._status(browser, state)
            assert status["error"] is True
            assert status["status"] == OidcEidMsg.authorization_error.value
        self._assert_not_verified(eppn)

    # d. unsolicited, handled, malformed, provider errors

    def test_unknown_state(self) -> None:
        eppn = self.test_unverified_user_eppn
        with self.session_cookie(self.browser, eppn) as browser:
            self._verify_identity_start(browser)
            response = self._callback(browser, "not-a-known-state", self.build_claims(FREJA, self.test_user_nin, OP_A))
        assert response.status_code == HTTPStatus.FOUND
        location = urlparse(response.headers["Location"])
        assert location.path == "/errors"
        assert parse_qs(location.query)["ctx"] == ["oidc_response_unsolicited"]
        assert all(fake.finish_calls == [] for fake in self.fakes.values())
        self._assert_not_verified(eppn)

    def test_no_state(self) -> None:
        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            response = self._callback(browser, "", query="code=mock_code")
        assert response.status_code == HTTPStatus.FOUND
        assert urlparse(response.headers["Location"]).path == "/errors"

    def test_state_without_client_is_unsolicited(self) -> None:
        eppn = self.test_unverified_user_eppn
        with self.session_cookie(self.browser, eppn) as browser:
            state, _issuer = self._verify_identity_start(browser)
            # the OP is no longer configured
            del self.app.oidc_clients[OP_A]
            response = self._callback(browser, state, self.build_claims(FREJA, self.test_user_nin, OP_A))
        assert response.status_code == HTTPStatus.FOUND
        assert urlparse(response.headers["Location"]).path == "/errors"
        assert self.fakes[OP_A].finish_calls == []
        self._assert_not_verified(eppn)

    def test_replayed_state(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        eppn = self.test_unverified_user_eppn
        with self.session_cookie(self.browser, eppn) as browser:
            state, issuer = self._verify_identity_start(browser)
            claims = self.build_claims(FREJA, self.test_user_nin, issuer)
            first = self._callback(browser, state, claims)
            assert first.status_code == HTTPStatus.FOUND
            assert urlparse(first.headers["Location"]).path != "/errors"
            second = self._callback(browser, state, claims)

        assert second.status_code == HTTPStatus.FOUND
        location = urlparse(second.headers["Location"])
        assert location.path == "/errors"
        assert parse_qs(location.query)["ctx"] == ["oidc_response_unsolicited"]
        # the action ran once only
        assert len(self.fakes[OP_A].finish_calls) == 1
        self._verify_user_parameters(eppn, num_mfa_tokens=0, identity_verified=True, num_proofings=1)

    def test_duplicate_parameters_terminate_the_request(self) -> None:
        eppn = self.test_unverified_user_eppn
        with self.session_cookie(self.browser, eppn) as browser:
            state, _issuer = self._verify_identity_start(browser)
            response = self._callback(browser, state, query=f"state={state}&code=one&code=two")

            assert response.status_code == HTTPStatus.FOUND
            assert "/testing-verify-identity/" in response.headers["Location"]
            assert self.fakes[OP_A].finish_calls == []
            status = self._status(browser, state)
            assert status["error"] is True
            assert status["status"] == OidcEidMsg.authorization_error.value
        self._assert_not_verified(eppn)

    def test_malformed_response_without_state(self) -> None:
        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            self._verify_identity_start(browser)
            response = self._callback(browser, "", query=f"code=one&code=two&iss={OP_A}")
        assert response.status_code == HTTPStatus.FOUND
        location = urlparse(response.headers["Location"])
        assert location.path == "/errors"
        assert parse_qs(location.query)["ctx"] == ["oidc_response_fail"]

    def test_late_response_from_other_op_without_matching_state(self, mocker: MockerFixture) -> None:
        """A response from OP B with an unknown state is unsolicited, it is not an iss mismatch of OP A"""
        stats_count = mocker.patch.object(self.app.stats, "count")
        eppn = self.test_unverified_user_eppn
        with self.session_cookie(self.browser, eppn) as browser:
            self._verify_identity_start(browser)  # pending request to OP A
            response = self._callback(browser, "", query=f"state=unknown&code=mock_code&iss={OP_B}")
        assert response.status_code == HTTPStatus.FOUND
        location = urlparse(response.headers["Location"])
        assert parse_qs(location.query)["ctx"] == ["oidc_response_unsolicited"]
        assert "authn_iss_mismatch" not in [c.kwargs.get("name") for c in stats_count.call_args_list]
        assert all(fake.finish_calls == [] for fake in self.fakes.values())
        self._assert_not_verified(eppn)

    def test_unknown_iss_without_matching_state(self) -> None:
        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            response = self._callback(browser, "", query="state=unknown&code=mock_code&iss=https://other.example.com")
        assert parse_qs(urlparse(response.headers["Location"]).query)["ctx"] == ["oidc_response_unsolicited"]

    def test_provider_error_response(self) -> None:
        eppn = self.test_unverified_user_eppn
        with self.session_cookie(self.browser, eppn) as browser:
            state, _issuer = self._verify_identity_start(browser)
            response = self._callback(browser, state, query=f"state={state}&error=access_denied")

            assert response.status_code == HTTPStatus.FOUND
            assert "/testing-verify-identity/" in response.headers["Location"]
            assert self.fakes[OP_A].finish_calls == []
            status = self._status(browser, state)
            assert status["error"] is True
            assert status["status"] == OidcEidMsg.authorization_error.value
        self._assert_not_verified(eppn)

    def test_token_exchange_failure(self) -> None:
        eppn = self.test_unverified_user_eppn
        self.fakes[OP_A].raise_on_finish = OidcRpError("token exchange failed")
        with self.session_cookie(self.browser, eppn) as browser:
            state, _issuer = self._verify_identity_start(browser)
            response = self._callback(browser, state)
            assert response.status_code == HTTPStatus.FOUND
            status = self._status(browser, state)
            assert status["error"] is True
            assert status["status"] == OidcEidMsg.authorization_error.value
        self._assert_not_verified(eppn)

    # e. missing claims

    def test_missing_birthdate(self) -> None:
        eppn = self.test_unverified_user_eppn
        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            method=FREJA,
            expect_msg=ProofingMsg.attribute_missing,
            expect_error=True,
            eppn=eppn,
            drop=(oidc_claims.CLAIM_BIRTHDATE,),
        )
        self._assert_not_verified(eppn)

    def test_missing_birthdate_eidas(self) -> None:
        eppn = self.test_unverified_user_eppn
        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            method=EIDAS,
            expect_msg=ProofingMsg.attribute_missing,
            expect_error=True,
            eppn=eppn,
            drop=(oidc_claims.CLAIM_BIRTHDATE,),
        )
        self._assert_not_verified(eppn)

    @pytest.mark.parametrize("claim", ["acr", "auth_time"])
    def test_missing_acr_or_auth_time(self, claim: str) -> None:
        eppn = self.test_unverified_user_eppn
        self.reauthn(
            "/verify-identity",
            frontend_action=FrontendAction.VERIFY_IDENTITY,
            method=FREJA,
            expect_msg=OidcEidMsg.method_not_available,
            expect_error=True,
            eppn=eppn,
            drop=(claim,),
        )
        self._assert_not_verified(eppn)

    def test_userinfo_merged(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        self.app.conf.fetch_userinfo = True
        eppn = self.test_unverified_user_eppn
        with self.session_cookie(self.browser, eppn) as browser:
            state, issuer = self._verify_identity_start(browser)
            claims = self.build_claims(FREJA, self.test_user_nin, issuer, drop=(oidc_claims.CLAIM_BIRTHDATE,))
            fake = self.fakes[OP_A]
            fake.claims = claims
            fake.tokens = {"access_token": "access_token"}
            fake.userinfo_response = {
                oidc_claims.CLAIM_BIRTHDATE: "1978-01-01",
                oidc_claims.CLAIM_PERSONAL_IDENTITY_NUMBER: self.test_user_wrong_nin.number,
            }
            response = browser.get(f"/authn-callback?state={state}&code=mock_code")
            assert response.status_code == HTTPStatus.FOUND
            status = self._status(browser, state)
            assert status["status"] == OidcEidMsg.identity_verify_success.value
        # the NIN of the ID token won
        self._verify_user_parameters(
            eppn, identity=self.test_user_nin, identity_verified=True, num_mfa_tokens=0, num_proofings=1
        )

    def _userinfo_callback(self, id_token_drop: tuple[str, ...], userinfo: dict[str, Any]) -> tuple[str, str]:
        self.app.conf.fetch_userinfo = True
        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            state, issuer = self._verify_identity_start(browser)
            claims = self.build_claims(FREJA, self.test_user_nin, issuer, drop=id_token_drop)
            fake = self.fakes[OP_A]
            fake.claims = claims
            fake.tokens = {"access_token": "access_token"}
            fake.userinfo_response = userinfo
            browser.get(f"/authn-callback?state={state}&code=mock_code")
            status = self._status(browser, state)
        return str(status["status"]), state

    @pytest.mark.parametrize("dropped", ["acr", "auth_time"])
    def test_userinfo_can_not_supply_acr_or_auth_time(self, dropped: str) -> None:
        userinfo = {"acr": LOA3, "auth_time": int(time.time()), "iss": OP_A}
        status, _ = self._userinfo_callback((dropped,), userinfo)
        assert status == OidcEidMsg.method_not_available.value
        self._assert_not_verified(self.test_unverified_user_eppn)

    def test_id_token_acr_wins_over_userinfo(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        # userinfo claims a higher level than the ID token, and an acr below the required one is not used either
        status, _ = self._userinfo_callback((), {"acr": LOA2})
        assert status == OidcEidMsg.identity_verify_success.value

    def test_userinfo_acr_does_not_raise_low_id_token_acr(self) -> None:
        self.app.conf.fetch_userinfo = True
        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            state, issuer = self._verify_identity_start(browser)
            self.fakes[OP_A].claims = self.build_claims(FREJA, self.test_user_nin, issuer, acr=LOA2)
            self.fakes[OP_A].tokens = {"access_token": "access_token"}
            self.fakes[OP_A].userinfo_response = {"acr": LOA3}
            browser.get(f"/authn-callback?state={state}&code=mock_code")
            assert self._status(browser, state)["status"] == OidcEidMsg.authn_context_mismatch.value
        self._assert_not_verified(self.test_unverified_user_eppn)

    def test_userinfo_failure(self) -> None:
        self.app.conf.fetch_userinfo = True
        eppn = self.test_unverified_user_eppn
        self.fakes[OP_A].raise_on_userinfo = OidcRpError("userinfo failed")
        with self.session_cookie(self.browser, eppn) as browser:
            state, issuer = self._verify_identity_start(browser)
            self._callback(browser, state, self.build_claims(FREJA, self.test_user_nin, issuer))
            status = self._status(browser, state)
            assert status["status"] == OidcEidMsg.authorization_error.value
        self._assert_not_verified(eppn)

    # f. the authorization request

    def _install_real_client(
        self, issuer: str, key: SigningKey | None = None, conf: SwedenConnectOidcClientConfig | None = None
    ) -> StaticHttpClient:
        """Replace the fake client of an OP with the real one, talking to a static (in-memory) OpenID Provider."""
        if conf is None:
            (conf,) = [p for p in self.app.conf.providers if p.issuer == issuer]
        signing_key = key or keys.signing_key_from_jwk(keys.generate_rsa_jwk(), "RS256", "op-key")
        metadata = ProviderMetadata(issuer, issuer).to_dict()
        http = StaticHttpClient()
        http.add_json(f"{issuer}/.well-known/openid-configuration", metadata)
        http.add_json(metadata["jwks_uri"], signing_key.to_public_jwks())
        self.signing_keys = getattr(self, "signing_keys", {})
        self.signing_keys[issuer] = signing_key
        self.metadata = metadata
        client: OidcRpClient = GrindvaktOidcRpClient(
            conf, [get_external_url(self.app, "oidceid.authn_callback")], http=http
        )
        self.app.oidc_clients[issuer] = client
        return http

    def _auth_query(self, location: str) -> dict[str, list[str]]:
        return parse_qs(urlparse(location).query)

    def test_authorization_request_freja(self) -> None:
        self._install_real_client(OP_A)
        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            location = self._start(browser, "/verify-identity", FREJA, FrontendAction.VERIFY_IDENTITY)
            state, issuer = self._pending_authn(browser)
            with browser.session_transaction() as sess:
                authn = sess.oidceid.rp.authns[OIDCState(state)]
                nonce = authn.nonce
                assert authn.code_verifier
                assert authn.redirect_uri == get_external_url(self.app, "oidceid.authn_callback")
        assert location is not None
        assert location.startswith(self.metadata["authorization_endpoint"])
        query = self._auth_query(location)
        assert issuer == OP_A
        assert query["client_id"] == [CLIENT_ID]
        assert query["response_type"] == ["code"]
        assert query["state"] == [state]
        assert query["nonce"] == [nonce]
        assert query["code_challenge_method"] == ["S256"]
        assert "code_challenge" in query
        assert query["redirect_uri"] == [get_external_url(self.app, "oidceid.authn_callback")]
        assert query["scope"] == [" ".join(oidc_claims.scopes_for_method(ProofingMethods.FREJA))]
        # force_authn for verify identity
        assert query["prompt"] == ["login"]
        # the required level is requested with an essential acr claim, never with acr_values
        assert "acr_values" not in query
        id_token = json.loads(query["claims"][0])["id_token"]
        assert id_token["acr"] == {"essential": True, "values": [LOA3]}
        assert id_token["auth_time"] == {"essential": True}
        assert id_token[oidc_claims.CLAIM_BIRTHDATE] == {"essential": True}
        assert id_token[oidc_claims.CLAIM_GIVEN_NAME] == {"essential": True}
        assert oidc_claims.CLAIM_PERSONAL_IDENTITY_NUMBER in id_token
        assert oidc_claims.CLAIM_PRID not in id_token

    def test_authorization_request_eidas(self) -> None:
        self._install_real_client(OP_B)
        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            location = self._start(browser, "/verify-identity", EIDAS, FrontendAction.VERIFY_IDENTITY)
        assert location is not None
        query = self._auth_query(location)
        assert query["scope"] == [" ".join(oidc_claims.scopes_for_method(ProofingMethods.EIDAS))]
        assert "acr_values" not in query
        id_token = json.loads(query["claims"][0])["id_token"]
        assert id_token["acr"]["essential"] is True
        assert id_token["acr"]["values"] == [
            self.app.conf.loa_authn_context_map[loa] for loa in self.app.conf.foreign_required_loa
        ]
        assert id_token[oidc_claims.CLAIM_PRID] == {"essential": True}
        assert id_token[oidc_claims.CLAIM_PRID_PERSISTENCE] == {"essential": True}

    def test_authorization_request_without_forced_authn(self) -> None:
        self.app.conf.frontend_action_authn_parameters[FrontendAction.VERIFY_IDENTITY].force_authn = False
        self._install_real_client(OP_A)
        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            location = self._start(browser, "/verify-identity", FREJA, FrontendAction.VERIFY_IDENTITY)
        assert location is not None
        assert "prompt" not in self._auth_query(location)

    def test_authorization_request_authn_provider(self) -> None:
        self.app.conf.method_authn_provider = {FREJA: "https://id.oidc.se/authn-provider/freja"}
        self._install_real_client(OP_A)
        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            location = self._start(browser, "/verify-identity", FREJA, FrontendAction.VERIFY_IDENTITY)
        assert location is not None
        assert self._auth_query(location)[oidc_claims.PARAM_AUTHN_PROVIDER] == [
            "https://id.oidc.se/authn-provider/freja"
        ]

    # g. the OP is chosen per method

    def test_each_method_goes_to_its_own_op(self) -> None:
        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            freja_url = self._start(browser, "/verify-identity", FREJA, FrontendAction.VERIFY_IDENTITY)
            eidas_url = self._start(browser, "/verify-identity", EIDAS, FrontendAction.VERIFY_IDENTITY)
            with browser.session_transaction() as sess:
                issuers = {authn.method: authn.oidc_issuer for authn in sess.oidceid.rp.authns.values()}
        assert freja_url is not None
        assert eidas_url is not None
        assert freja_url.startswith(f"{OP_A}/authorize")
        assert eidas_url.startswith(f"{OP_B}/authorize")
        assert issuers == {FREJA: OP_A, EIDAS: OP_B}

    def test_callback_is_handled_by_the_op_of_the_request(self, mocker: MockerFixture) -> None:
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            self._start(browser, "/verify-identity", FREJA, FrontendAction.VERIFY_IDENTITY)
            freja_state, _ = self._pending_authn(browser)
            self._start(browser, "/verify-identity", EIDAS, FrontendAction.VERIFY_IDENTITY)
            # the second request does not remove the first one
            with browser.session_transaction() as sess:
                assert len(sess.oidceid.rp.authns) == 2
            self._callback(browser, freja_state, self.build_claims(FREJA, self.test_user_nin, OP_A))
        assert len(self.fakes[OP_A].finish_calls) == 1
        assert self.fakes[OP_B].finish_calls == []

    # h. the real client with private_key_jwt

    def test_private_key_jwt_with_real_client(self, tmp_path: Path, mocker: MockerFixture) -> None:
        mocker.patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data", return_value=None)
        mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync").side_effect = self.request_user_sync
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_path = tmp_path / "client_signing_key.pem"
        key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        conf = SwedenConnectOidcClientConfig(
            client_id=CLIENT_ID,
            issuer=OP_A,
            token_endpoint_auth_method="private_key_jwt",
            client_signing_key_path=key_path,
            client_signing_key_kid="client-key",
        )
        http = self._install_real_client(OP_A, conf=conf)
        signing_key = self.signing_keys[OP_A]

        eppn = self.test_unverified_user_eppn
        with self.session_cookie(self.browser, eppn) as browser:
            location = self._start(browser, "/verify-identity", FREJA, FrontendAction.VERIFY_IDENTITY)
            assert location is not None
            state, issuer = self._pending_authn(browser)
            nonce = self._auth_query(location)["nonce"][0]

            claims = self.build_claims(FREJA, self.test_user_nin, issuer)
            claims["nonce"] = nonce
            http.add_json(
                self.metadata["token_endpoint"],
                {"access_token": "access_token", "token_type": "Bearer", "id_token": jwt.sign(signing_key, claims)},
            )
            response = browser.get(f"/authn-callback?state={state}&code=mock_code&iss={OP_A}")
            assert response.status_code == HTTPStatus.FOUND
            status = self._status(browser, state)
            assert status["status"] == OidcEidMsg.identity_verify_success.value

        (token_request,) = http.requests_to(self.metadata["token_endpoint"])
        assert token_request.form is not None
        form = dict(token_request.form)
        assert form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        assert form["client_assertion"]
        assert "client_secret" not in form
        assert form["code_verifier"]
        # the authorization code grant token request has no scope parameter (RFC 6749 4.1.3): the scopes are bound
        # to the code at the authorization request, so the per-method scopes do not need to be repeated here
        assert "scope" not in form
        assert not any(name.lower() == "authorization" for name, _ in (token_request.headers or []))
        self._verify_user_parameters(
            eppn, identity=self.test_user_nin, identity_verified=True, num_mfa_tokens=0, num_proofings=1
        )

    def test_nonce_mismatch_with_real_client(self) -> None:
        http = self._install_real_client(OP_A)
        eppn = self.test_unverified_user_eppn
        with self.session_cookie(self.browser, eppn) as browser:
            self._start(browser, "/verify-identity", FREJA, FrontendAction.VERIFY_IDENTITY)
            state, issuer = self._pending_authn(browser)
            claims = self.build_claims(FREJA, self.test_user_nin, issuer)
            claims["nonce"] = "another-nonce"
            http.add_json(
                self.metadata["token_endpoint"],
                {
                    "access_token": "access_token",
                    "token_type": "Bearer",
                    "id_token": jwt.sign(self.signing_keys[OP_A], claims),
                },
            )
            response = browser.get(f"/authn-callback?state={state}&code=mock_code&iss={OP_A}")
            assert response.status_code == HTTPStatus.FOUND
            status = self._status(browser, state)
            assert status["status"] == OidcEidMsg.authorization_error.value
        self._assert_not_verified(eppn)

    def test_callback_without_iss_is_rejected_before_token_exchange(self) -> None:
        # all OPs share one redirect URI: without iss (RFC 9207) the code must not be sent to any token endpoint
        http = self._install_real_client(OP_A)
        eppn = self.test_unverified_user_eppn
        with self.session_cookie(self.browser, eppn) as browser:
            location = self._start(browser, "/verify-identity", FREJA, FrontendAction.VERIFY_IDENTITY)
            assert location is not None
            state, issuer = self._pending_authn(browser)
            claims = self.build_claims(FREJA, self.test_user_nin, issuer)
            claims["nonce"] = self._auth_query(location)["nonce"][0]
            http.add_json(
                self.metadata["token_endpoint"],
                {
                    "access_token": "access_token",
                    "token_type": "Bearer",
                    "id_token": jwt.sign(self.signing_keys[OP_A], claims),
                },
            )
            response = browser.get(f"/authn-callback?state={state}&code=mock_code")
            assert response.status_code == HTTPStatus.FOUND
        assert http.requests_to(self.metadata["token_endpoint"]) == []
        self._assert_not_verified(eppn)

    def test_get_status_of_pending_request(self) -> None:
        with self.session_cookie(self.browser, self.test_unverified_user_eppn) as browser:
            self._start(browser, "/verify-identity", FREJA, FrontendAction.VERIFY_IDENTITY, frontend_state="my state")
            state, _issuer = self._pending_authn(browser)
            status = self._status(browser, state)
        assert status["frontend_action"] == FrontendAction.VERIFY_IDENTITY.value
        assert status["frontend_state"] == "my state"
        assert status["method"] == FREJA
        assert status["error"] is False
        assert "status" not in status

    def test_mfa_login_resets_mfa_action(self) -> None:
        eppn = self.test_user.eppn
        with self.session_cookie_anon(self.browser) as browser:
            with browser.session_transaction() as sess:
                sess.mfa_action.login_ref = "test login ref"
                sess.mfa_action.eppn = eppn
                sess.mfa_action.success = True  # left over from something else
            self._start(browser, "/mfa-authenticate", FREJA, FrontendAction.LOGIN_MFA_AUTHN)
            state, _issuer = self._pending_authn(browser)
            with browser.session_transaction() as sess:
                assert sess.mfa_action.login_ref == "test login ref"
                assert sess.mfa_action.eppn == eppn
                assert sess.mfa_action.authn_req_ref == state
                assert not sess.mfa_action.success
