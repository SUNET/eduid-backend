import pytest
from pytest_mock import MockerFixture

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials.external import SwedenConnectCredential
from eduid.userdb.idp import IdPUser
from eduid.webapp.idp.assurance import AuthnState
from eduid.webapp.idp.idp_authn import UsedCredential, UsedWhere
from eduid.webapp.idp.tests.test_api import IdPAPITests


class TestAuthnStateSwedenConnect(IdPAPITests):
    """Tests for how AuthnState classifies SwedenConnectCredential levels"""

    @pytest.fixture(autouse=True)
    def setup(self, setup_api: None, mocker: MockerFixture) -> None:
        self.mocker = mocker

    def _swamid_al3_used(self, level: str) -> bool:
        user = self.app.userdb.lookup_user(self.test_user.eppn)
        assert isinstance(user, IdPUser)
        cred = SwedenConnectCredential(level=level, created_by="test")
        user.credentials.add(cred)
        used = UsedCredential(credential_id=cred.key, ts=utc_now(), source=UsedWhere.SSO)
        self.mocker.patch.object(AuthnState, "_gather_credentials", return_value=[used])
        with self.app.test_request_context():
            state = AuthnState(user, self.mocker.MagicMock(), self.mocker.MagicMock())
        assert state.external_mfa_used is True
        return state.swamid_al3_used

    @pytest.mark.parametrize(("level", "expected"), [("loa4", True), ("loa3", True), ("loa2", False)])
    def test_sweden_connect_level(self, level: str, expected: bool) -> None:
        assert self._swamid_al3_used(level) is expected
