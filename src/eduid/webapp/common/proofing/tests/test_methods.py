from pytest_mock import MockerFixture

from eduid.common.config.base import FrontendAction, ProofingConfigMixin
from eduid.userdb.credentials.external import TrustFramework
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.common.proofing.methods import (
    ProofingMethodFreja,
    ProofingMethods,
    ProofingMethodSAML,
    ProofingMethodSverigeID,
    get_proofing_method,
)
from eduid.webapp.common.proofing.swedenconnect.session_info import NinSessionInfo

_ISSUER = "https://op.example.com"


def _session_info(**extra: object) -> dict[str, object]:
    return {
        "issuer": _ISSUER,
        "authn_info": [("http://id.elegnamnden.se/loa/1.0/loa3", [], "2026-01-01T12:00:00Z")],
        "ava": {
            "personalIdentityNumber": ["197801012369"],
            "givenName": ["Ulla"],
            "sn": ["Alm"],
            "dateOfBirth": ["1978-01-01"],
        },
        **extra,
    }


def test_sverigeid_method() -> None:
    config = ProofingConfigMixin(freja_idp="freja-idp", sverigeid_idp="sverigeid-idp")
    method = get_proofing_method("sverigeid", FrontendAction.VERIFY_IDENTITY, config)
    assert isinstance(method, ProofingMethodSverigeID)
    assert isinstance(method, ProofingMethodSAML)
    assert method.method is ProofingMethods.SVERIGEID
    assert method.framework == TrustFramework.SWECONN
    assert method.idp == "sverigeid-idp"
    assert method.required_loa == ["loa3", "loa4"]


def test_freja_method_is_not_sverigeid() -> None:
    config = ProofingConfigMixin(freja_idp="freja-idp", sverigeid_idp="sverigeid-idp")
    method = get_proofing_method("freja", FrontendAction.VERIFY_IDENTITY, config)
    assert isinstance(method, ProofingMethodFreja)
    assert not isinstance(method, ProofingMethodSverigeID)
    assert method.idp == "freja-idp"
    assert method.required_loa == ["loa3"]


def test_sverigeid_method_required_loa_follows_config() -> None:
    config = ProofingConfigMixin(sverigeid_idp="sverigeid-idp", sverigeid_required_loa=["loa4"])
    method = get_proofing_method("sverigeid", FrontendAction.VERIFY_IDENTITY, config)
    assert method is not None
    assert isinstance(method, ProofingMethodSAML)
    assert method.required_loa == ["loa4"]


def test_sverigeid_method_without_idp_is_not_available() -> None:
    config = ProofingConfigMixin(freja_idp="freja-idp")
    assert get_proofing_method("sverigeid", FrontendAction.VERIFY_IDENTITY, config) is None


def test_sverigeid_parses_nin_session_info() -> None:
    config = ProofingConfigMixin(sverigeid_idp="sverigeid-idp")
    method = get_proofing_method("sverigeid", FrontendAction.VERIFY_IDENTITY, config)
    assert method is not None
    parsed = method.parse_session_info(_session_info(), backdoor=False)  # type: ignore[arg-type]
    assert parsed.error is None
    assert isinstance(parsed.info, NinSessionInfo)
    assert parsed.info.attributes.nin == "197801012369"


def test_sverigeid_missing_attribute() -> None:
    config = ProofingConfigMixin(sverigeid_idp="sverigeid-idp")
    method = get_proofing_method("sverigeid", FrontendAction.VERIFY_IDENTITY, config)
    assert method is not None
    info = _session_info()
    info["ava"] = {"givenName": ["Ulla"]}
    parsed = method.parse_session_info(info, backdoor=False)  # type: ignore[arg-type]
    assert parsed.error == ProofingMsg.attribute_missing


def test_sverigeid_backdoor_uses_nin_cookie(mocker: MockerFixture) -> None:
    config = ProofingConfigMixin(sverigeid_idp="sverigeid-idp")
    method = get_proofing_method("sverigeid", FrontendAction.VERIFY_IDENTITY, config)
    assert method is not None
    request = mocker.MagicMock()
    mocker.patch("eduid.webapp.common.proofing.methods.request", new=request)
    request.cookies = {"nin": "199001011234"}
    parsed = method.parse_session_info(_session_info(), backdoor=True)  # type: ignore[arg-type]
    assert isinstance(parsed.info, NinSessionInfo)
    assert parsed.info.attributes.nin == "199001011234"
    request.cookies = {}
    assert method.parse_session_info(_session_info(), backdoor=True).error == ProofingMsg.malformed_identity  # type: ignore[arg-type]
