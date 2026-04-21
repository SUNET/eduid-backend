"""
Focused unit tests for parse_mfa_register_args in eduid.webapp.common.proofing.mfa_signup.

These tests exercise each early-return branch plus the happy path using lightweight
stand-ins — no Flask app is spun up.
"""

from unittest.mock import MagicMock

from eduid.common.models.saml_models import BaseSessionInfo
from eduid.userdb.credentials.external import TrustFramework
from eduid.webapp.common.authn.acs_registry import ACSArgs, ACSResult
from eduid.webapp.common.proofing.base import GenericResult
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.common.proofing.mfa_signup import MfaRegisterParsed, parse_mfa_register_args


def _make_args(proofing_method: object = None) -> ACSArgs:
    """Build a minimal ACSArgs-like object for testing."""
    args = MagicMock(spec=ACSArgs)
    args.proofing_method = proofing_method
    args.backdoor = False
    args.session_info = MagicMock()
    args.authn_req = MagicMock()
    return args


def _make_proofing_method(framework: TrustFramework = TrustFramework.BANKID) -> MagicMock:
    pm = MagicMock()
    pm.framework = framework
    return pm


def test_returns_method_not_available_when_no_proofing_method() -> None:
    """args.proofing_method is None → helper returns ACSResult with the given message."""
    args = _make_args(proofing_method=None)
    sentinel_msg = ProofingMsg.attribute_missing

    result = parse_mfa_register_args(
        args,
        common_saml_checks=MagicMock(return_value=None),
        get_proofing_functions=MagicMock(),
        method_not_available_msg=sentinel_msg,
        app_name="test",
        config=MagicMock(),
    )

    assert isinstance(result, ACSResult)
    assert result.message is sentinel_msg


def test_returns_early_on_common_saml_checks_failure() -> None:
    """common_saml_checks returns a non-None ACSResult → helper returns the same result."""
    args = _make_args(proofing_method=_make_proofing_method())
    saml_error = ACSResult(message=ProofingMsg.attribute_missing)

    result = parse_mfa_register_args(
        args,
        common_saml_checks=MagicMock(return_value=saml_error),
        get_proofing_functions=MagicMock(),
        method_not_available_msg=ProofingMsg.malformed_identity,
        app_name="test",
        config=MagicMock(),
    )

    assert result is saml_error


def test_returns_parse_error() -> None:
    """parse_session_info returns a result with non-None error → helper returns ACSResult with that error."""
    pm = _make_proofing_method()
    pm.parse_session_info.return_value = MagicMock(error=ProofingMsg.attribute_missing, info=None)

    args = _make_args(proofing_method=pm)

    result = parse_mfa_register_args(
        args,
        common_saml_checks=MagicMock(return_value=None),
        get_proofing_functions=MagicMock(),
        method_not_available_msg=ProofingMsg.malformed_identity,
        app_name="test",
        config=MagicMock(),
    )

    assert isinstance(result, ACSResult)
    assert result.message is ProofingMsg.attribute_missing


def test_happy_path_returns_parsed() -> None:
    """All steps succeed → helper returns MfaRegisterParsed with session_info, framework, loa."""
    fake_session_info = MagicMock(spec=BaseSessionInfo)
    pm = _make_proofing_method(framework=TrustFramework.EIDAS)
    pm.parse_session_info.return_value = MagicMock(error=None, info=fake_session_info)

    fake_proofing = MagicMock()
    fake_proofing.get_current_loa.return_value = GenericResult(result="loa3", error=None)
    get_proofing_functions = MagicMock(return_value=fake_proofing)

    args = _make_args(proofing_method=pm)

    result = parse_mfa_register_args(
        args,
        common_saml_checks=MagicMock(return_value=None),
        get_proofing_functions=get_proofing_functions,
        method_not_available_msg=ProofingMsg.malformed_identity,
        app_name="myapp",
        config=object(),
    )

    assert isinstance(result, MfaRegisterParsed)
    assert result.session_info is fake_session_info
    assert result.framework == TrustFramework.EIDAS
    assert result.loa == "loa3"
