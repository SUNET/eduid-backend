from collections.abc import Mapping
from http import HTTPStatus
from typing import Any

import pytest

from eduid.common.config.base import FrontendAction
from eduid.common.rpc.msg_relay import FullPostalAddress, Name, OfficialAddress
from eduid.userdb.proofing import LetterProofingState, LetterProofingStateDB, NinProofingElement
from eduid.userdb.proofing.element import SentLetterElement
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.support.app import SupportApp, support_init_app

__author__ = "lundberg"


class SupportAppTests(EduidAPITestCase[SupportApp]):
    """Base TestCase for those tests that need a full environment setup"""

    app: SupportApp

    @pytest.fixture(autouse=True)
    def setup(self, setup_api: None) -> None:
        self.test_user_eppn = "hubba-bubba"
        self.client = self.app.test_client()
        self.update_test_user()

    @classmethod
    def load_app(cls, config: Mapping[str, Any]) -> SupportApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return support_init_app("testing", config)

    @pytest.fixture(scope="class")
    @classmethod
    def update_config(cls) -> dict[str, Any]:
        config = cls._get_base_config()
        config.update(
            {
                "support_personnel": ["hubba-bubba"],
                "authn_service_url_login": "https://localhost/login",
                "authn_service_url_logout": "https://localhost/logout",
                "eduid_static_url": "https://testing.eduid.se/static/",
            }
        )
        return config

    def update_test_user(self) -> None:
        # add webauthn credential
        self.add_security_key_to_user(self.test_user_eppn, keyhandle="test_keyhandle")

    # Authentication
    def test_no_authentication(self) -> None:
        # Unauthenticated request
        resp = self.browser.get("/search-form")
        assert resp.status_code == HTTPStatus.OK
        assert resp.headers.get("HX-Redirect") == self.app.conf.authn_service_url_login

    def test_authentication_no_mfa(self) -> None:
        # Authenticated request
        self.set_authn_action(eppn=self.test_user_eppn, frontend_action=FrontendAction.LOGIN, mock_mfa=False)
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            resp = client.get("/search-form")
            assert resp.status_code == HTTPStatus.OK
            assert resp.headers.get("HX-Redirect") == self.app.conf.authn_service_url_login

    def test_authentication_mfa(self) -> None:
        # Authenticated request with MFA
        self.set_authn_action(eppn=self.test_user_eppn, frontend_action=FrontendAction.LOGIN, mock_mfa=True)
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            resp = client.get("/search-form")
        assert resp.status_code == HTTPStatus.OK
        assert resp.headers.get("HX-Redirect") is None

    # Search
    def test_search_existing_user(self) -> None:
        existing_mail_address = self.test_user.mail_addresses.to_list()[0]
        self.set_authn_action(eppn=self.test_user_eppn, frontend_action=FrontendAction.LOGIN, mock_mfa=True)
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            response = client.post("/search", data={"query": f"{existing_mail_address.email}"})
        assert b"1 user was found using query" in response.data
        # look for the generated credential id for a webauthn security key
        assert b"sha256:4e8d75214d48bc726323fea84f7ac0e3af0e59a3853e251d30652c95af387e75" in response.data

    def test_search_does_not_show_official_address(self) -> None:
        address = FullPostalAddress(
            Name=Name(GivenName="Tolvan", Surname="Tolvansson"),
            OfficialAddress=OfficialAddress(Address2="Testgatan 12", PostalCode="11455", City="Teststad"),
        )
        letter_state = LetterProofingState(
            eppn=self.test_user_eppn,
            nin=NinProofingElement(
                number="190001019802", created_by="test", is_verified=False, verification_code="abc123"
            ),
            proofing_letter=SentLetterElement(is_sent=True, address=address),
            id=None,
            modified_ts=None,
        )
        LetterProofingStateDB(self.app.conf.mongo_uri).save(letter_state, is_in_database=False)

        existing_mail_address = self.test_user.mail_addresses.to_list()[0]
        self.set_authn_action(eppn=self.test_user_eppn, frontend_action=FrontendAction.LOGIN, mock_mfa=True)
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            response = client.post("/search", data={"query": f"{existing_mail_address.email}"})
        # The letter proofing state is shown, but not the address the letter was sent to
        assert "Letter sent to official address (folkbokföringsadressen)".encode() in response.data
        assert b"Official address</th>" not in response.data
        assert b"Testgatan" not in response.data
        assert b"Teststad" not in response.data

    def test_search_non_existing_user(self) -> None:
        non_existing_mail_address = "not_in_db@example.com"
        self.set_authn_action(eppn=self.test_user_eppn, frontend_action=FrontendAction.LOGIN, mock_mfa=True)
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            response = client.post("/search", data={"query": non_existing_mail_address})
        assert b"No user found" in response.data
