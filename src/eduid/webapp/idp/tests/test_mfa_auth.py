from http import HTTPStatus

import pytest
from pytest_mock import MockerFixture
from werkzeug.test import TestResponse

from eduid.common.models.saml2 import EduidAuthnContextClass
from eduid.userdb import User
from eduid.userdb.credentials.external import TrustFramework
from eduid.userdb.idp import IdPUser
from eduid.vccs.client import VCCSClient
from eduid.webapp.common.api.testing import CSRFTestClient
from eduid.webapp.common.session import session
from eduid.webapp.common.session.eduid_session import SessionFactory
from eduid.webapp.common.session.namespaces import MfaAction, RequestRef
from eduid.webapp.common.session.redis_session import SessionOutOfSync
from eduid.webapp.idp.helpers import IdPAction
from eduid.webapp.idp.tests.test_api import IdPAPITests
from eduid.webapp.idp.views import mfa_auth
from eduid.webapp.idp.views.mfa_auth import CheckResult, _check_external_mfa


class TestCheckExternalMfa(IdPAPITests):
    """Tests for the login_ref binding in _check_external_mfa"""

    @pytest.fixture(autouse=True)
    def setup(self, setup_api: None, mocker: MockerFixture) -> None:
        self.mocker = mocker

    def _setup(self, login_ref: str | None) -> tuple[IdPUser, MfaAction]:
        cred = self.add_test_user_external_mfa_cred(trust_framework=TrustFramework.SWECONN, trust_level="loa3")
        user = self.app.userdb.lookup_user(self.test_user.eppn)
        assert user is not None
        mfa_action = MfaAction(
            success=True,
            eppn=user.eppn,
            login_ref=login_ref,
            credential_used=cred.key,
            issuer="https://issuer.example.com",
            authn_context="http://id.elegnamnden.se/loa/1.0/loa3",
        )
        return user, mfa_action

    def test_login_ref_matching_accepted(self) -> None:
        user, mfa_action = self._setup(login_ref="the-ref")
        log_spy = self.mocker.patch("eduid.webapp.common.session.namespaces.IdP_Namespace.log_credential_used")
        with self.app.test_request_context():
            result = _check_external_mfa(mfa_action, user, RequestRef("the-ref"))
        log_spy.assert_called_once()
        assert result is not None
        assert result.credential is not None

    def test_success_without_login_ref_rejected(self) -> None:
        user, mfa_action = self._setup(login_ref=None)
        with self.app.test_request_context():
            assert _check_external_mfa(mfa_action, user, RequestRef("the-ref")) is None

    def test_success_with_other_login_ref_rejected(self) -> None:
        user, mfa_action = self._setup(login_ref="other-ref")
        with self.app.test_request_context():
            assert _check_external_mfa(mfa_action, user, RequestRef("the-ref")) is None


class TestMfaAuthGrantConsumption(IdPAPITests):
    """The external MFA grant is one-time: a lost session write while consuming it must fail the request."""

    def _start(self) -> tuple[CSRFTestClient, str, str]:
        """Log in with password, return (device, ref, mfa target) for a request requiring MFA."""
        self.mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        cred = self.add_test_user_external_mfa_cred(trust_framework=TrustFramework.SWECONN, trust_level="loa3")
        self.cred_key = cred.key
        self.add_test_user_tou()
        device = self.browser
        _ref_result = self._get_login_ref(
            device,
            self.saml2_client,
            {"authn_context_class_ref": [EduidAuthnContextClass.REFEDS_MFA.value], "comparison": "exact"},
            False,
            None,
        )
        assert isinstance(_ref_result, tuple)
        ref, _ = _ref_result
        _next = self._call_next(device, ref)
        assert _next.payload["action"] == IdPAction.USERNAMEPWAUTH.value
        assert self.default_user.password is not None
        self._call_pwauth(
            device=device,
            target=_next.payload["target"],
            ref=ref,
            username=self.default_user.eppn,
            password=self.default_user.password,
        )
        _next = self._call_next(device, ref)
        assert _next.payload["action"] == IdPAction.MFA.value
        return device, ref, _next.payload["target"]

    def _grant_external_mfa(self, device: CSRFTestClient, ref: str) -> None:
        with self.session_cookie_anon(device) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    sess.mfa_action.success = True
                    sess.mfa_action.eppn = self.test_user.eppn
                    sess.mfa_action.login_ref = ref
                    sess.mfa_action.credential_used = self.cred_key
                    sess.mfa_action.issuer = "https://issuer.example.com"
                    sess.mfa_action.authn_context = "http://id.elegnamnden.se/loa/1.0/loa3"

    def _post_mfa(self, device: CSRFTestClient, target: str, ref: str) -> TestResponse:
        with self.session_cookie_anon(device) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"ref": ref, "csrf_token": sess.get_csrf_token()}
                return client.post(target, json=data)

    def test_lost_write_consuming_grant_fails_closed(self) -> None:
        device, ref, target = self._start()
        self._grant_external_mfa(device, ref)

        real_check = mfa_auth._check_external_mfa

        def conflicting_check(mfa_action: MfaAction, user: User, ref: RequestRef) -> CheckResult | None:
            # A sibling request commits to the same backend session while this request is in flight,
            # retaining mfa_action (it never saw our delete).
            factory = self.app.session_interface
            assert isinstance(factory, SessionFactory)
            sibling = factory.manager.get_session(meta=session.meta, new=False)
            sibling["sibling"] = "writer"
            sibling.commit()
            return real_check(mfa_action, user, ref)

        patched = self.mocker.patch.object(mfa_auth, "_check_external_mfa", side_effect=conflicting_check)
        try:
            response = self._post_mfa(device, target, ref)
        except SessionOutOfSync:
            pass  # propagated by the test client
        else:
            assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
            assert not (response.json or {}).get("payload", {}).get("finished")

        # The grant is still in the backend, since our delete was lost
        self.mocker.stop(patched)
        # Retrying consumes the grant exactly once, as a normal flow would
        retry = self._post_mfa(device, target, ref)
        assert retry.json is not None
        assert retry.json["payload"]["finished"] is True
        # ... and it can not be reused a second time
        again = self._post_mfa(device, target, ref)
        assert again.json is not None
        assert not again.json["payload"].get("finished")
