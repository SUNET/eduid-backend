import pytest
from pytest_mock import MockerFixture

from eduid.userdb.credentials.external import TrustFramework
from eduid.userdb.idp import IdPUser
from eduid.webapp.common.session.namespaces import MfaAction, RequestRef
from eduid.webapp.idp.tests.test_api import IdPAPITests
from eduid.webapp.idp.views.mfa_auth import _check_external_mfa


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
