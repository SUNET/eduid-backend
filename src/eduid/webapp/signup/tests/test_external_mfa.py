import json
import logging
from datetime import date, timedelta

import pytest
from pytest_mock import MockerFixture
from werkzeug.test import TestResponse

from eduid.common.config.base import FrontendAction
from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials.external import TrustFramework
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
