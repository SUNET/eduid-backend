import json
import logging
from datetime import date, timedelta
from typing import Any

import pytest
from pytest_mock import MockerFixture
from werkzeug.test import TestResponse

from eduid.common.config.base import FrontendAction
from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials.external import (
    BankIDCredential,
    EidasCredential,
    FrejaCredential,
    SwedenConnectCredential,
    TrustFramework,
)
from eduid.webapp.common.session.namespaces import (
    AuthnRequestRef,
    ExternalMfaSignupIdentity,
    OIDCState,
    RP_AuthnRequest,
    SP_AuthnRequest,
)
from eduid.webapp.signup.helpers import SignupMsg
from eduid.webapp.signup.tests.test_app import SignupTests

logger = logging.getLogger(__name__)

_FINISH_URL = "https://eduid.se/profile/ext-return/{app_name}/{authn_id}"


class ExternalMfaSignupTests(SignupTests):
    """Tests for the /external-mfa-register endpoint."""

    @pytest.fixture(autouse=True)
    def setup(self, setup_api: None, mocker: MockerFixture) -> None:
        self.mocker = mocker

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _seed_bankid_authn(
        self,
        authn_id: str = "authn-1",
        nin: str = "198001011234",
        minutes_ago: int = 0,
        consumed: bool = False,
        frontend_action: FrontendAction = FrontendAction.SIGNUP_EXTERNAL_MFA,
        has_identity: bool = True,
        error: bool = False,
        set_authn_instant: bool = True,
    ) -> None:
        ident: ExternalMfaSignupIdentity | None = None
        if has_identity:
            ident = ExternalMfaSignupIdentity(
                given_name="Anna",
                surname="Andersson",
                date_of_birth=date(1980, 1, 1),
                nin=nin,
                framework=TrustFramework.BANKID,
                loa="loa3",
            )
        authn_instant = utc_now() - timedelta(minutes=minutes_ago) if set_authn_instant else None
        req = SP_AuthnRequest(
            authn_id=AuthnRequestRef(authn_id),
            frontend_action=frontend_action,
            finish_url=_FINISH_URL,
            consumed=consumed,
            authn_instant=authn_instant,
            error=error,
            external_mfa_signup_identity=ident,
        )
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                sess.bankid.sp.authns[AuthnRequestRef(authn_id)] = req

    def _seed_freja_eid_authn(
        self,
        authn_id: str = "authn-freja-1",
        nin: str = "198001011234",
        minutes_ago: int = 0,
        consumed: bool = False,
        frontend_action: FrontendAction = FrontendAction.SIGNUP_EXTERNAL_MFA,
        has_identity: bool = True,
        error: bool = False,
    ) -> None:
        ident: ExternalMfaSignupIdentity | None = None
        if has_identity:
            ident = ExternalMfaSignupIdentity(
                given_name="Britta",
                surname="Borg",
                date_of_birth=date(1980, 1, 1),
                nin=nin,
                framework=TrustFramework.FREJA,
                loa="loa3",
            )
        req = RP_AuthnRequest(
            authn_id=OIDCState(authn_id),
            frontend_action=frontend_action,
            finish_url=_FINISH_URL,
            consumed=consumed,
            authn_instant=utc_now() - timedelta(minutes=minutes_ago),
            error=error,
            external_mfa_signup_identity=ident,
        )
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                sess.freja_eid.rp.authns[OIDCState(authn_id)] = req

    def _call_external_mfa_register(self, app_name: str, authn_id: str) -> TestResponse:
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = {"app_name": app_name, "authn_id": authn_id, "csrf_token": csrf_token}
            return client.post(
                "/external-mfa-register",
                data=json.dumps(data),
                content_type=self.content_type_json,
            )

    # ------------------------------------------------------------------
    # Happy path
    # ------------------------------------------------------------------

    def test_ok(self) -> None:
        """A valid bankid authn is accepted and stored in the signup session."""
        self._seed_bankid_authn()
        response = self._call_external_mfa_register("bankid", "authn-1")
        assert response.status_code == 200
        state = self.get_response_payload(response)["state"]
        assert state["external_mfa"]["completed"] is True
        assert state["external_mfa"]["app_name"] == "bankid"
        assert state["external_mfa"]["given_name"] == "Anna"
        assert state["external_mfa"]["surname"] == "Andersson"
        assert state["external_mfa"]["masked_nin"] == "198001**-****"
        # verify session was updated
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                assert sess.signup.external_mfa is not None
                assert sess.signup.external_mfa.nin == "198001011234"
                assert sess.bankid.sp.authns[AuthnRequestRef("authn-1")].consumed is True

    def test_ok_freja_eid(self) -> None:
        """A valid freja_eid authn (RP_AuthnRequest) is accepted."""
        self._seed_freja_eid_authn()
        response = self._call_external_mfa_register("freja_eid", "authn-freja-1")
        assert response.status_code == 200
        state = self.get_response_payload(response)["state"]
        assert state["external_mfa"]["completed"] is True
        assert state["external_mfa"]["app_name"] == "freja_eid"
        assert state["external_mfa"]["given_name"] == "Britta"
        assert state["external_mfa"]["masked_nin"] == "198001**-****"

    # ------------------------------------------------------------------
    # Error cases
    # ------------------------------------------------------------------

    def test_app_unsupported(self) -> None:
        response = self._call_external_mfa_register("other", "authn-1")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.external_mfa_not_found,
        )

    def test_authn_missing(self) -> None:
        response = self._call_external_mfa_register("bankid", "does-not-exist")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.external_mfa_not_found,
        )

    def test_wrong_action(self) -> None:
        self._seed_bankid_authn(frontend_action=FrontendAction.LOGIN_MFA_AUTHN)
        response = self._call_external_mfa_register("bankid", "authn-1")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.external_mfa_wrong_action,
        )

    def test_error_flagged(self) -> None:
        self._seed_bankid_authn(error=True)
        response = self._call_external_mfa_register("bankid", "authn-1")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.external_mfa_not_verified,
        )

    def test_missing_identity(self) -> None:
        self._seed_bankid_authn(has_identity=False)
        response = self._call_external_mfa_register("bankid", "authn-1")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.external_mfa_not_verified,
        )

    def test_too_old(self) -> None:
        self._seed_bankid_authn(minutes_ago=6)
        response = self._call_external_mfa_register("bankid", "authn-1")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.external_mfa_too_old,
        )

    def test_already_consumed(self) -> None:
        self._seed_bankid_authn(consumed=True)
        response = self._call_external_mfa_register("bankid", "authn-1")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.external_mfa_already_consumed,
        )

    def test_user_already_created(self) -> None:
        self._seed_bankid_authn()
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                sess.signup.user_created = True
        response = self._call_external_mfa_register("bankid", "authn-1")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.user_already_exists,
        )

    def test_no_authn_instant(self) -> None:
        """An authn without authn_instant is rejected as not verified."""
        self._seed_bankid_authn(set_authn_instant=False)
        response = self._call_external_mfa_register("bankid", "authn-1")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.external_mfa_not_verified,
        )

    def _seed_bankid_authn_with_identity(
        self, ident: ExternalMfaSignupIdentity, authn_id: str = "authn-1"
    ) -> None:
        req = SP_AuthnRequest(
            authn_id=AuthnRequestRef(authn_id),
            frontend_action=FrontendAction.SIGNUP_EXTERNAL_MFA,
            finish_url=_FINISH_URL,
            consumed=False,
            authn_instant=utc_now(),
            error=False,
            external_mfa_signup_identity=ident,
        )
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                sess.bankid.sp.authns[AuthnRequestRef(authn_id)] = req

    def test_identity_missing_discriminator(self) -> None:
        """Identity with neither nin nor eidas_prid is rejected as not verified."""
        ident = ExternalMfaSignupIdentity(
            given_name="Anna",
            surname="Andersson",
            date_of_birth=date(1980, 1, 1),
            framework=TrustFramework.BANKID,
            loa="loa3",
        )
        self._seed_bankid_authn_with_identity(ident)
        response = self._call_external_mfa_register("bankid", "authn-1")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.external_mfa_not_verified,
        )
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                assert sess.signup.external_mfa is None
                assert sess.bankid.sp.authns[AuthnRequestRef("authn-1")].consumed is False

    def test_identity_with_both_discriminators(self) -> None:
        """Identity with both nin and eidas_prid is rejected (ambiguous)."""
        from eduid.userdb.identity import PridPersistence as _PridPersistence

        ident = ExternalMfaSignupIdentity(
            given_name="Anna",
            surname="Andersson",
            date_of_birth=date(1980, 1, 1),
            nin="198001011234",
            eidas_prid="DE:abc",
            eidas_prid_persistence=_PridPersistence.A,
            country_code="DE",
            framework=TrustFramework.EIDAS,
            loa="eidas-nf-sub",
        )
        self._seed_bankid_authn_with_identity(ident)
        response = self._call_external_mfa_register("bankid", "authn-1")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.external_mfa_not_verified,
        )

    def test_identity_prid_missing_country_code(self) -> None:
        """Identity with eidas_prid but no country_code is rejected."""
        from eduid.userdb.identity import PridPersistence as _PridPersistence

        ident = ExternalMfaSignupIdentity(
            given_name="Diana",
            surname="Diaz",
            date_of_birth=date(1990, 6, 15),
            eidas_prid="DE:abc",
            eidas_prid_persistence=_PridPersistence.A,
            country_code=None,
            framework=TrustFramework.EIDAS,
            loa="eidas-nf-sub",
        )
        self._seed_bankid_authn_with_identity(ident)
        response = self._call_external_mfa_register("bankid", "authn-1")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.external_mfa_not_verified,
        )

    def _seed_samleid_authn(
        self,
        authn_id: str = "authn-samleid-1",
        nin: str = "198001011234",
        framework: TrustFramework = TrustFramework.BANKID,
        minutes_ago: int = 0,
        consumed: bool = False,
        frontend_action: FrontendAction = FrontendAction.SIGNUP_EXTERNAL_MFA,
        has_identity: bool = True,
        error: bool = False,
        set_authn_instant: bool = True,
    ) -> None:
        ident: ExternalMfaSignupIdentity | None = None
        if has_identity:
            ident = ExternalMfaSignupIdentity(
                given_name="Signe",
                surname="Svensson",
                date_of_birth=date(1980, 1, 1),
                nin=nin,
                framework=framework,
                loa="loa3",
            )
        authn_instant = utc_now() - timedelta(minutes=minutes_ago) if set_authn_instant else None
        req = SP_AuthnRequest(
            authn_id=AuthnRequestRef(authn_id),
            frontend_action=frontend_action,
            finish_url=_FINISH_URL,
            consumed=consumed,
            authn_instant=authn_instant,
            error=error,
            external_mfa_signup_identity=ident,
        )
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                sess.samleid.sp.authns[AuthnRequestRef(authn_id)] = req

    def _seed_eidas_foreign_authn(
        self,
        authn_id: str = "authn-eidas-1",
        prid: str = "DE:abc",
        country_code: str = "DE",
        minutes_ago: int = 0,
        consumed: bool = False,
        frontend_action: FrontendAction = FrontendAction.SIGNUP_EXTERNAL_MFA,
        has_identity: bool = True,
        error: bool = False,
    ) -> None:
        ident: ExternalMfaSignupIdentity | None = None
        if has_identity:
            from eduid.userdb.identity import PridPersistence as _PridPersistence

            ident = ExternalMfaSignupIdentity(
                given_name="Diana",
                surname="Diaz",
                date_of_birth=date(1990, 6, 15),
                eidas_prid=prid,
                eidas_prid_persistence=_PridPersistence.A,
                country_code=country_code,
                framework=TrustFramework.EIDAS,
                loa="eidas-nf-sub",
            )
        req = SP_AuthnRequest(
            authn_id=AuthnRequestRef(authn_id),
            frontend_action=frontend_action,
            finish_url=_FINISH_URL,
            consumed=consumed,
            authn_instant=utc_now() - timedelta(minutes=minutes_ago),
            error=error,
            external_mfa_signup_identity=ident,
        )
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                sess.eidas.sp.authns[AuthnRequestRef(authn_id)] = req

    # ------------------------------------------------------------------
    # Collision checks
    # ------------------------------------------------------------------

    def test_nin_collision(self) -> None:
        """Signup is hard-blocked when NIN already belongs to an existing verified user.

        The test user (hubba-bubba / new_user_example) already has a verified NIN
        of 197801011234, so we seed the authn with that same NIN to trigger the
        collision path without needing to modify the user.
        """
        # Verify the test user actually has the NIN we will collide against
        existing = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert existing is not None
        assert existing.identities.nin is not None
        collision_nin = existing.identities.nin.number  # "197801011234"

        self._seed_bankid_authn(nin=collision_nin)
        response = self._call_external_mfa_register("bankid", "authn-1")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.identity_already_registered,
        )

        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                # collision => nothing stored, nothing consumed
                assert sess.signup.external_mfa is None
                assert sess.bankid.sp.authns[AuthnRequestRef("authn-1")].consumed is False

    def test_prid_collision(self) -> None:
        """Signup is hard-blocked when eIDAS PRID already belongs to an existing verified user.

        The test user (hubba-bubba / new_user_example) already has a verified eIDAS
        identity with PRID unique/prid/string/1, so we seed the authn with that same
        PRID to trigger the collision path.
        """
        existing = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert existing is not None
        eidas_ident = existing.identities.eidas
        assert eidas_ident is not None
        collision_prid = eidas_ident.prid  # "unique/prid/string/1"

        self._seed_eidas_foreign_authn(prid=collision_prid, country_code="DE")
        response = self._call_external_mfa_register("eidas", "authn-eidas-1")
        self._check_api_response(
            response,
            status=200,
            type_="POST_SIGNUP_EXTERNAL_MFA_REGISTER_FAIL",
            message=SignupMsg.identity_already_registered,
        )

    def test_collision_check_skipped_when_no_identity_fields(self) -> None:
        """Helper returns None when no NIN or PRID is present."""
        from eduid.webapp.signup.views import _existing_user_for_identity

        empty_ident = ExternalMfaSignupIdentity(
            given_name="X",
            surname="Y",
            date_of_birth=date(1980, 1, 1),
            framework=TrustFramework.BANKID,
            loa="loa3",
        )
        assert _existing_user_for_identity(empty_ident) is None

    # ------------------------------------------------------------------
    # Clear external MFA state
    # ------------------------------------------------------------------

    def _call_external_mfa_clear(self) -> TestResponse:
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = {"csrf_token": csrf_token}
            return client.post(
                "/external-mfa-clear",
                data=json.dumps(data),
                content_type=self.content_type_json,
            )

    def test_external_mfa_clear_ok(self) -> None:
        self._seed_bankid_authn()
        # Seed the state first
        resp = self._call_external_mfa_register("bankid", "authn-1")
        assert resp.status_code == 200
        # Now clear it
        resp = self._call_external_mfa_clear()
        assert resp.status_code == 200
        state = self.get_response_payload(resp)["state"]
        assert state["external_mfa"]["completed"] is False
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                assert sess.signup.external_mfa is None

    def test_external_mfa_clear_is_idempotent(self) -> None:
        # Clearing when nothing is stored should still succeed
        resp = self._call_external_mfa_clear()
        assert resp.status_code == 200
        state = self.get_response_payload(resp)["state"]
        assert state["external_mfa"]["completed"] is False

    def test_external_mfa_clear_rejected_after_user_created(self) -> None:
        self._seed_bankid_authn()
        self._call_external_mfa_register("bankid", "authn-1")
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                sess.signup.user_created = True
        resp = self._call_external_mfa_clear()
        payload = self.get_response_payload(resp)
        assert payload["message"] == SignupMsg.user_already_exists.value

    # ------------------------------------------------------------------
    # create-user with external MFA — happy path tests
    # ------------------------------------------------------------------

    def test_create_user_with_external_mfa_bankid(self) -> None:
        """A new user created via the BankID external-MFA flow gets a verified NIN and BankIDCredential."""
        self._seed_bankid_authn(nin="198001011234", authn_id="authn-1")
        self._call_external_mfa_register("bankid", "authn-1")

        # Complete the remaining signup prerequisites via the session shortcut
        self._prepare_for_create_user(
            given_name="Anna",
            surname="Andersson",
            email="anna.andersson@example.com",
        )

        result = self._create_user()
        assert result.response.status_code == 200

        # Retrieve the eppn from the session after user creation
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                eppn = sess.common.eppn
        assert eppn is not None

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user is not None

        # Verified NIN must be present
        assert user.identities.nin is not None
        assert user.identities.nin.number == "198001011234"
        assert user.identities.nin.is_verified is True

        # Exactly one BankIDCredential
        bankid_creds = [c for c in user.credentials.to_list() if isinstance(c, BankIDCredential)]
        assert len(bankid_creds) == 1
        assert bankid_creds[0].level == "loa3"

        # Proofing log must have an entry for this eppn
        log_entries = list(self.app.proofing_log._coll.find({"eduPersonPrincipalName": eppn}))
        external_mfa_entries = [e for e in log_entries if e.get("proofing_method") == "bankid"]
        assert len(external_mfa_entries) == 1
        assert external_mfa_entries[0]["nin"] == "198001011234"

    def test_create_user_with_external_mfa_eidas_prid(self) -> None:
        """A new user created via the eIDAS external-MFA flow gets a verified EIDASIdentity and EidasCredential."""
        self._seed_eidas_foreign_authn(
            prid="DE:abc123",
            country_code="DE",
            authn_id="authn-eidas-1",
        )
        self._call_external_mfa_register("eidas", "authn-eidas-1")

        self._prepare_for_create_user(
            given_name="Diana",
            surname="Diaz",
            email="diana.diaz@example.com",
        )

        result = self._create_user()
        assert result.response.status_code == 200

        # Retrieve the eppn from the session after user creation
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                eppn = sess.common.eppn
        assert eppn is not None

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user is not None

        # Verified EIDASIdentity must be present
        assert user.identities.eidas is not None
        assert user.identities.eidas.prid == "DE:abc123"
        assert user.identities.eidas.country_code == "DE"
        assert user.identities.eidas.is_verified is True

        # Exactly one EidasCredential
        eidas_creds = [c for c in user.credentials.to_list() if isinstance(c, EidasCredential)]
        assert len(eidas_creds) == 1
        assert eidas_creds[0].level == "eidas-nf-sub"

        # Proofing log must have an entry for this eppn
        log_entries = list(self.app.proofing_log._coll.find({"eduPersonPrincipalName": eppn}))
        external_mfa_entries = [e for e in log_entries if e.get("proofing_method") == "eidas"]
        assert len(external_mfa_entries) == 1
        assert external_mfa_entries[0]["country_code"] == "DE"

    # ------------------------------------------------------------------
    # Parametrized NIN-based create-user variants
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        ("app_name", "framework", "credential_class", "proofing_version_attr"),
        [
            # bankid SP — TrustFramework.BANKID → BankIDCredential
            ("bankid", TrustFramework.BANKID, BankIDCredential, "bankid_proofing_version"),
            # samleid SP with bankid-style NIN — same credential type as bankid
            ("samleid", TrustFramework.BANKID, BankIDCredential, "bankid_proofing_version"),
            # samleid SP with Swedish Freja (SwedenConnect) NIN
            ("samleid", TrustFramework.SWECONN, SwedenConnectCredential, "freja_proofing_version"),
            # freja_eid RP — TrustFramework.FREJA → FrejaCredential
            ("freja_eid", TrustFramework.FREJA, FrejaCredential, "freja_eid_proofing_version"),
        ],
    )
    def test_create_user_with_external_mfa_nin(
        self,
        app_name: str,
        framework: TrustFramework,
        credential_class: type[BankIDCredential | SwedenConnectCredential | FrejaCredential | EidasCredential],
        proofing_version_attr: str,
    ) -> None:
        """Parametrized NIN-based create-user test covering bankid, samleid (BANKID + SWECONN), and freja_eid."""
        nin = "198001011234"
        authn_id = f"authn-{app_name}-1"
        email = f"test.{app_name}.{framework.value}@example.com"

        # Seed the appropriate authn into the correct session namespace
        if app_name == "bankid":
            self._seed_bankid_authn(nin=nin, authn_id=authn_id)
        elif app_name == "samleid":
            self._seed_samleid_authn(nin=nin, authn_id=authn_id, framework=framework)
        elif app_name == "freja_eid":
            self._seed_freja_eid_authn(nin=nin, authn_id=authn_id)
        else:
            raise ValueError(f"Unexpected app_name: {app_name}")

        self._call_external_mfa_register(app_name, authn_id)
        self._prepare_for_create_user(given_name="Test", surname="Testsson", email=email)

        result = self._create_user()
        assert result.response.status_code == 200

        # Retrieve eppn from session
        with self.session_cookie_anon(self.browser) as client:
            with client.session_transaction() as sess:
                eppn = sess.common.eppn
        assert eppn is not None

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user is not None

        # Verified NIN must be present
        assert user.identities.nin is not None
        assert user.identities.nin.number == nin
        assert user.identities.nin.is_verified is True

        # Exactly one credential of the expected subclass at loa3
        matching_creds = [c for c in user.credentials.to_list() if isinstance(c, credential_class)]
        assert len(matching_creds) == 1
        assert matching_creds[0].level == "loa3"

        # Proofing log entry with correct proofing_method and proofing_version
        expected_version: Any = getattr(self.app.conf, proofing_version_attr)
        log_entries = list(self.app.proofing_log._coll.find({"eduPersonPrincipalName": eppn}))
        external_mfa_entries = [e for e in log_entries if e.get("proofing_method") == app_name]
        assert len(external_mfa_entries) == 1
        assert external_mfa_entries[0]["nin"] == nin
        assert external_mfa_entries[0]["proofing_version"] == expected_version
