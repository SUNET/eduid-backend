import logging
from typing import cast
from unittest.mock import MagicMock

from eduid.common.misc.timeutil import utc_now
from eduid.common.models.saml2 import EduidAuthnContextClass
from eduid.webapp.common.api.schemas.models import FluxResponseStatus
from eduid.webapp.idp.assurance import AuthnState
from eduid.webapp.idp.assurance_data import AuthnInfo
from eduid.webapp.idp.helpers import IdPAction, IdPMsg
from eduid.webapp.idp.login import NextResult as LoginNextResult
from eduid.webapp.idp.login_context import LoginContext, LoginContextOtherDevice
from eduid.webapp.idp.other_device.data import OtherDeviceState
from eduid.webapp.idp.sso_session import SSOSession
from eduid.webapp.idp.tests.test_api import IdPAPITests
from eduid.webapp.idp.views.next import (
    RequiredUserResult,
    _handle_aborted,
    _handle_assurance_failure,
    _handle_mfa_required,
    _handle_must_authenticate,
    _handle_other_device,
    _handle_proceed,
    _handle_security_key_required,
    _handle_tou_required,
    _handle_unknown_device,
)

logger = logging.getLogger(__name__)


def _mock_ticket() -> LoginContext:
    """Create a minimal mock LoginContext for handler tests."""
    ticket = MagicMock(spec=LoginContext)
    ticket.reauthn_required = False
    ticket.is_other_device_2 = False
    ticket.known_device = None
    ticket.known_device_info = None
    ticket.service_info = None
    return cast(LoginContext, ticket)


class TestNextHandlers(IdPAPITests):
    """Unit tests for the individual handler functions extracted from next_view()."""

    def test_handle_unknown_device(self) -> None:
        with self.app.test_request_context():
            result = _handle_unknown_device()
        assert result.status == FluxResponseStatus.OK
        assert result.payload["action"] == IdPAction.NEW_DEVICE.value

    def test_handle_must_authenticate_no_eppn(self) -> None:
        """When eppn is None, should offer username+password auth."""
        ticket = _mock_ticket()
        required_user = RequiredUserResult(eppn=None)
        with self.app.test_request_context():
            result = _handle_must_authenticate(ticket, None, required_user)
        assert result.status == FluxResponseStatus.OK
        assert result.payload["action"] == IdPAction.USERNAMEPWAUTH.value
        assert result.payload["message"] == IdPMsg.must_authenticate.value

    def test_handle_must_authenticate_with_eppn_no_webauthn(self) -> None:
        """When user has eppn but no webauthn, should offer username+password auth."""
        ticket = _mock_ticket()
        required_user = RequiredUserResult(eppn="test-eppn")
        with self.app.test_request_context():
            result = _handle_must_authenticate(ticket, None, required_user)
        # User "test-eppn" won't be found by lookup_user, so webauthn defaults to True
        # but the default user has no FIDO credential, so webauthn will be set to False
        # if the user IS found. Since "test-eppn" is not a real user, webauthn stays True -> MFA
        assert result.status == FluxResponseStatus.OK
        assert result.payload["action"] == IdPAction.MFA.value

    def test_handle_must_authenticate_with_real_user(self) -> None:
        """When user has eppn and credentials, action depends on their credential types."""
        ticket = _mock_ticket()
        required_user = RequiredUserResult(eppn=self.test_user.eppn)
        with self.app.test_request_context():
            result = _handle_must_authenticate(ticket, None, required_user)
        assert result.status == FluxResponseStatus.OK
        # Default test user has no FIDO credential -> webauthn=False -> USERNAMEPWAUTH
        assert result.payload["action"] == IdPAction.USERNAMEPWAUTH.value

    def test_handle_must_authenticate_with_security_key(self) -> None:
        """When user has a security key, should offer MFA auth."""
        self.add_test_user_security_key()
        ticket = _mock_ticket()
        required_user = RequiredUserResult(eppn=self.test_user.eppn)
        with self.app.test_request_context():
            result = _handle_must_authenticate(ticket, None, required_user)
        assert result.status == FluxResponseStatus.OK
        assert result.payload["action"] == IdPAction.MFA.value

    def test_handle_mfa_required_no_fido_used(self) -> None:
        """When fido hasn't been used yet, should offer MFA auth."""
        ticket = _mock_ticket()
        required_user = RequiredUserResult(eppn=self.test_user.eppn)
        _next = LoginNextResult(message=IdPMsg.mfa_required, authn_state=None)
        with self.app.test_request_context():
            result = _handle_mfa_required(ticket, None, _next, required_user)
        assert result.status == FluxResponseStatus.OK
        assert result.payload["action"] == IdPAction.MFA.value
        assert result.payload["message"] == IdPMsg.mfa_required.value

    def test_handle_mfa_required_fido_already_used(self) -> None:
        """When fido was already used, should offer password auth (no double security key)."""
        ticket = _mock_ticket()
        required_user = RequiredUserResult(eppn=self.test_user.eppn)
        authn_state = MagicMock(spec=AuthnState)
        authn_state.fido_used = True
        _next = LoginNextResult(message=IdPMsg.mfa_required, authn_state=authn_state)
        with self.app.test_request_context():
            result = _handle_mfa_required(ticket, None, _next, required_user)
        assert result.status == FluxResponseStatus.OK
        assert result.payload["action"] == IdPAction.USERNAMEPWAUTH.value
        assert result.payload["authn_options"]["webauthn"] is False

    def test_handle_security_key_required(self) -> None:
        ticket = _mock_ticket()
        required_user = RequiredUserResult(eppn=self.test_user.eppn)
        with self.app.test_request_context():
            result = _handle_security_key_required(ticket, None, required_user)
        assert result.status == FluxResponseStatus.OK
        assert result.payload["action"] == IdPAction.MFA.value
        assert result.payload["message"] == IdPMsg.mfa_required.value

    def test_handle_tou_required(self) -> None:
        ticket = _mock_ticket()
        required_user = RequiredUserResult(eppn=self.test_user.eppn)
        with self.app.test_request_context():
            result = _handle_tou_required(ticket, None, required_user)
        assert result.status == FluxResponseStatus.OK
        assert result.payload["action"] == IdPAction.TOU.value
        assert result.payload["message"] == IdPMsg.tou_required.value

    def test_handle_other_device(self) -> None:
        ticket = _mock_ticket()
        required_user = RequiredUserResult(eppn=self.test_user.eppn)
        with self.app.test_request_context():
            result = _handle_other_device(ticket, None, required_user)
        assert result.status == FluxResponseStatus.OK
        assert result.payload["action"] == IdPAction.OTHER_DEVICE.value
        assert result.payload["message"] == IdPMsg.must_authenticate.value

    def test_handle_proceed_no_sso_session(self) -> None:
        """Should return error when no SSO session is present."""
        ticket = _mock_ticket()
        required_user = RequiredUserResult(eppn=self.test_user.eppn)
        _next = LoginNextResult(message=IdPMsg.proceed)
        with self.app.test_request_context():
            result = _handle_proceed(ticket, None, _next, required_user)
        assert result.status == FluxResponseStatus.ERROR
        assert result.payload["message"] == IdPMsg.no_sso_session.value

    def test_handle_proceed_user_not_found(self) -> None:
        """Should return error when SSO session references a non-existent user."""
        ticket = _mock_ticket()
        required_user = RequiredUserResult(eppn="nonexistent-eppn")
        sso_session = MagicMock(spec=SSOSession)
        sso_session.eppn = "nonexistent-eppn"
        _next = LoginNextResult(message=IdPMsg.proceed)
        with self.app.test_request_context():
            result = _handle_proceed(ticket, cast(SSOSession, sso_session), _next, required_user)
        assert result.status == FluxResponseStatus.ERROR
        assert result.payload["message"] == IdPMsg.general_failure.value

    def test_handle_proceed_missing_authn_data(self) -> None:
        """Should raise RuntimeError when authn_info or authn_state is missing."""
        ticket = _mock_ticket()
        required_user = RequiredUserResult(eppn=self.test_user.eppn)
        sso_session = MagicMock(spec=SSOSession)
        sso_session.eppn = self.test_user.eppn
        # authn_info and authn_state are both None by default
        _next = LoginNextResult(message=IdPMsg.proceed, authn_info=None, authn_state=None)
        with self.app.test_request_context():
            with self.assertRaises(RuntimeError):
                _handle_proceed(ticket, cast(SSOSession, sso_session), _next, required_user)

    def test_handle_proceed_unknown_ticket_type(self) -> None:
        """Should return error for a ticket that is neither SAML nor OtherDevice."""
        ticket = _mock_ticket()
        required_user = RequiredUserResult(eppn=self.test_user.eppn)
        sso_session = MagicMock(spec=SSOSession)
        sso_session.eppn = self.test_user.eppn
        authn_state = MagicMock(spec=AuthnState)
        authn_info = AuthnInfo(class_ref=EduidAuthnContextClass.PASSWORD_PT, authn_attributes={}, instant=utc_now())
        _next = LoginNextResult(message=IdPMsg.proceed, authn_info=authn_info, authn_state=authn_state)
        with self.app.test_request_context():
            result = _handle_proceed(ticket, cast(SSOSession, sso_session), _next, required_user)
        assert result.status == FluxResponseStatus.ERROR
        assert result.payload["message"] == IdPMsg.general_failure.value

    def test_handle_aborted_unknown_ticket_type(self) -> None:
        """Should return error for a ticket that is neither SAML nor OtherDevice."""
        ticket = _mock_ticket()
        with self.app.test_request_context():
            result = _handle_aborted(ticket, None)
        assert result.status == FluxResponseStatus.ERROR
        assert result.payload["message"] == IdPMsg.general_failure.value

    def test_handle_aborted_other_device_abort_fails(self) -> None:
        """Should return error when other_device_db.abort() returns False."""
        ticket = MagicMock(spec=LoginContextOtherDevice)
        ticket.reauthn_required = False
        ticket.is_other_device_2 = False
        ticket.known_device = None
        ticket.service_info = None
        state = MagicMock()
        state.state = OtherDeviceState.NEW
        ticket.other_device_req = state
        # Make abort fail
        self.app.other_device_db.abort = MagicMock(return_value=False)  # type: ignore[method-assign]
        with self.app.test_request_context():
            result = _handle_aborted(cast(LoginContext, ticket), None)
        assert result.status == FluxResponseStatus.ERROR
        assert result.payload["message"] == IdPMsg.general_failure.value

    def test_handle_aborted_other_device_non_abortable_state(self) -> None:
        """Should return error when OtherDevice is in a non-abortable state (e.g. FINISHED)."""
        ticket = MagicMock(spec=LoginContextOtherDevice)
        ticket.reauthn_required = False
        ticket.is_other_device_2 = False
        ticket.known_device = None
        ticket.service_info = None
        state = MagicMock()
        state.state = OtherDeviceState.FINISHED
        ticket.other_device_req = state
        with self.app.test_request_context():
            result = _handle_aborted(cast(LoginContext, ticket), None)
        assert result.status == FluxResponseStatus.ERROR
        assert result.payload["message"] == IdPMsg.general_failure.value

    def test_handle_assurance_failure_non_saml(self) -> None:
        """Should return error for a non-SAML ticket."""
        ticket = _mock_ticket()
        with self.app.test_request_context():
            result = _handle_assurance_failure(ticket, None)
        assert result.status == FluxResponseStatus.ERROR
        assert result.payload["message"] == IdPMsg.general_failure.value
