from typing import Any, cast

import pytest
from pytest_mock import MockerFixture

from eduid.common.config.base import EduidEnvironment, FrontendAction
from eduid.userdb.element import ElementKey
from eduid.webapp.common.api.messages import CommonMsg
from eduid.webapp.common.authn.acs_registry import ACSResult
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.proofing.methods import ProofingMethod
from eduid.webapp.common.proofing.swedenconnect.flow import (
    SwedenConnectMsgs,
    apply_action_result,
    build_status_payload,
    remap_staging_nin,
    reset_mfa_action_for_login,
    sc_mfa_authenticate,
    sc_mfa_register,
    sc_verify_credential,
    sc_verify_identity,
    select_magic_cookie_idp,
)
from eduid.webapp.common.session.namespaces import AuthnRequestRef, MfaAction

NIN_MAP = {"199001011234": "198001011234"}


def _session_info(nin: str) -> SessionInfo:
    return cast(SessionInfo, {"ava": {"personalIdentityNumber": [nin]}})


@pytest.mark.parametrize("env", [EduidEnvironment.staging, EduidEnvironment.dev])
def test_remap_staging_nin_remaps(env: EduidEnvironment) -> None:
    res = remap_staging_nin(_session_info("199001011234"), environment=env, nin_attribute_map=NIN_MAP)
    assert res["ava"]["personalIdentityNumber"] == ["198001011234"]


def test_remap_staging_nin_unmapped_unchanged() -> None:
    res = remap_staging_nin(
        _session_info("190000000000"), environment=EduidEnvironment.staging, nin_attribute_map=NIN_MAP
    )
    assert res["ava"]["personalIdentityNumber"] == ["190000000000"]


def test_remap_staging_nin_noop_in_production() -> None:
    res = remap_staging_nin(
        _session_info("199001011234"), environment=EduidEnvironment.production, nin_attribute_map=NIN_MAP
    )
    assert res["ava"]["personalIdentityNumber"] == ["199001011234"]


def test_select_magic_cookie_idp() -> None:
    kw = {"freja_idp": "f", "bankid_idp": "b", "eidas_idp": "e"}
    assert select_magic_cookie_idp("freja", **kw) == "f"
    assert select_magic_cookie_idp("bankid", **kw) == "b"
    assert select_magic_cookie_idp("eidas", **kw) == "e"
    assert select_magic_cookie_idp("other", **kw) is None
    assert select_magic_cookie_idp("freja", freja_idp=None, bankid_idp="b", eidas_idp="e") is None


def test_build_status_payload(mocker: MockerFixture) -> None:
    authn = mocker.MagicMock()
    authn.frontend_action = FrontendAction.VERIFY_IDENTITY
    authn.frontend_state = "state"
    authn.method = "freja"
    authn.error = False
    authn.status = None
    assert build_status_payload("ref", authn) == {  # type: ignore[arg-type]
        "authn_id": "ref",
        "frontend_action": FrontendAction.VERIFY_IDENTITY.value,
        "frontend_state": "state",
        "method": "freja",
        "error": False,
    }
    authn.status = "x"
    assert build_status_payload("ref", authn)["status"] == "x"  # type: ignore[arg-type]


def test_apply_action_result_failure_and_temp_problem(mocker: MockerFixture) -> None:
    mocker.patch("eduid.webapp.common.proofing.swedenconnect.flow.redirect", side_effect=lambda u: u)
    authn = mocker.MagicMock()
    res: Any = apply_action_result(ACSResult(), authn, "http://finish", app=mocker.MagicMock())
    assert res == "http://finish"
    assert authn.status == CommonMsg.temp_problem.value
    assert authn.error is True
    assert authn.consumed is True


def test_apply_action_result_no_finish_url(mocker: MockerFixture) -> None:
    with pytest.raises(RuntimeError):
        apply_action_result(ACSResult(success=True), mocker.MagicMock(), None, app=mocker.MagicMock())


class _FakeSession:
    """Mimics EduidSession.mfa_action: a lazily created namespace that `del` resets."""

    def __init__(self, mfa_action: MfaAction) -> None:
        self._mfa_action: MfaAction | None = mfa_action

    @property
    def mfa_action(self) -> MfaAction:
        if self._mfa_action is None:
            self._mfa_action = MfaAction()
        return self._mfa_action

    @mfa_action.deleter
    def mfa_action(self) -> None:
        self._mfa_action = None


def test_reset_mfa_action_for_login_keeps_only_expected_keys(mocker: MockerFixture) -> None:
    old = MfaAction(
        success=True,
        eppn="hubba-bubba",
        login_ref="login-ref",
        authn_req_ref=AuthnRequestRef("old-ref"),
        credential_used=ElementKey("cred-id"),
        issuer="https://idp.example.com",
        authn_instant="2026-01-01T12:00:00Z",
        authn_context="http://id.elegnamnden.se/loa/1.0/loa3",
        required_loa=["loa3"],
    )
    fake = _FakeSession(old)
    mocker.patch("eduid.webapp.common.proofing.swedenconnect.flow.session", new=fake)

    reset_mfa_action_for_login(AuthnRequestRef("new-ref"))

    result = fake.mfa_action
    assert result.login_ref == "login-ref"
    assert result.eppn == "hubba-bubba"
    assert result.authn_req_ref == "new-ref"
    assert result.success is False
    assert result.credential_used is None
    assert result.issuer is None
    assert result.authn_instant is None
    assert result.authn_context is None
    assert result.framework is None
    assert result.required_loa == []
    assert result.webauthn_state is None


def test_sc_actions_run_common_checks(mocker: MockerFixture) -> None:
    """Every sc_* action must call the injected assurance checks and stop on their result."""
    msg = CommonMsg.temp_problem
    msgs = SwedenConnectMsgs(*[msg] * 10)
    blocked = ACSResult(message=CommonMsg.temp_problem)
    check = mocker.MagicMock(return_value=blocked)
    args = mocker.MagicMock()
    args.proofing_method = mocker.MagicMock(spec=ProofingMethod)
    app = mocker.MagicMock()
    user = mocker.MagicMock()

    assert sc_verify_identity(user, args, msgs, common_checks=check, app=app) is blocked
    assert sc_verify_credential(user, args, msgs, common_checks=check, app=app) is blocked
    assert sc_mfa_authenticate(args, msgs, common_checks=check, get_user=lambda: user, app=app) is blocked
    assert sc_mfa_register(args, msgs, common_checks=check, app=app) is blocked
    assert check.call_count == 4
    args.proofing_method.parse_session_info.assert_not_called()
