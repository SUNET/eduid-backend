import json
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from eduid.userdb.credentials.external import TrustFramework
from eduid.webapp.common.proofing.messages import ProofingMsg
from eduid.webapp.common.proofing.methods import ProofingMethodEidas, ProofingMethodFreja, ProofingMethods
from eduid.webapp.common.proofing.swedenconnect.session_info import ForeignEidSessionInfo, NinSessionInfo
from eduid.webapp.oidceid import claims
from eduid.webapp.oidceid.settings.common import OidcEidConfig

ISSUER = "https://op.example.com"
ACR = "http://id.elegnamnden.se/loa/1.0/loa3"
AUTH_TIME = 1767268800  # 2026-01-01T12:00:00Z

_CELERY = {"broker_url": "memory://"}


def _conf(**extra: Any) -> OidcEidConfig:
    return OidcEidConfig(mongo_uri="mongodb://localhost", celery=_CELERY, **extra)


FREJA_CLAIMS: dict[str, Any] = {
    "iss": ISSUER,
    "acr": ACR,
    "auth_time": AUTH_TIME,
    claims.CLAIM_PERSONAL_IDENTITY_NUMBER: "197801012369",
    "given_name": "Ulla",
    "family_name": "Alm",
    "name": "Ulla Alm",
    "birthdate": "1978-01-01",
}

EIDAS_CLAIMS: dict[str, Any] = {
    "iss": ISSUER,
    "acr": "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub",
    "auth_time": AUTH_TIME,
    claims.CLAIM_PRID: "XB:1bjrk7depnmhu7xn56kon3mlc9q1s0",
    claims.CLAIM_PRID_PERSISTENCE: "B",
    claims.CLAIM_EIDAS_PERSON_IDENTIFIER: "XB/SE/12345",
    "given_name": "Ulla",
    "family_name": "Alm",
    "birthdate": "1964-12-31",
    claims.CLAIM_EIDAS_COUNTRY: "XB",
    "txn": "_a1b2c3",
}


def _id_token_request(params: dict[str, str]) -> dict[str, Any]:
    request: dict[str, Any] = json.loads(params["claims"])
    id_token: dict[str, Any] = request["id_token"]
    return id_token


def test_build_authn_params_freja() -> None:
    conf = _conf()
    params = claims.build_authn_params(ProofingMethods.FREJA, ["loa3"], conf, force_authn=False)
    assert "acr_values" not in params
    assert "prompt" not in params
    assert claims.PARAM_AUTHN_PROVIDER not in params
    id_token = _id_token_request(params)
    assert id_token["acr"] == {"essential": True, "values": [conf.loa_authn_context_map["loa3"]]}
    for name in [
        claims.CLAIM_PERSONAL_IDENTITY_NUMBER,
        claims.CLAIM_COORDINATION_NUMBER,
        "given_name",
        "family_name",
        "birthdate",
        "name",
    ]:
        assert name in id_token


def test_build_authn_params_eidas() -> None:
    conf = _conf()
    params = claims.build_authn_params(ProofingMethods.EIDAS, ["eidas-nf-sub", "eidas-nf-high"], conf, False)
    id_token = _id_token_request(params)
    assert id_token["acr"] == {
        "essential": True,
        "values": [
            "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub",
            "http://id.elegnamnden.se/loa/1.0/eidas-nf-high",
        ],
    }
    for name in [
        "https://id.swedenconnect.se/claim/prid",
        "https://id.swedenconnect.se/claim/pridPersistence",
        "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
        "https://id.swedenconnect.se/claim/eidasCountry",
        "https://id.swedenconnect.se/claim/mappedPersonalIdentityNumber",
        "txn",
        "given_name",
        "family_name",
        "birthdate",
    ]:
        assert name in id_token


def test_build_authn_params_prompt_and_authn_provider() -> None:
    conf = _conf(method_authn_provider={"freja": "freja-provider"})
    params = claims.build_authn_params(ProofingMethods.FREJA, ["loa3"], conf, force_authn=True)
    assert params["prompt"] == "login"
    assert params["https://id.oidc.se/param/authnProvider"] == "freja-provider"
    # not configured for eidas
    params = claims.build_authn_params(ProofingMethods.EIDAS, ["eidas-nf-sub"], conf, force_authn=False)
    assert "https://id.oidc.se/param/authnProvider" not in params


def test_unsupported_method() -> None:
    conf = _conf()
    with pytest.raises(ValueError, match="Unsupported"):
        claims.build_authn_params(ProofingMethods.SVIPE_ID, ["loa3"], conf, False)
    with pytest.raises(ValueError, match="Unsupported"):
        claims.scopes_for_method(ProofingMethods.SVIPE_ID)
    with pytest.raises(ValueError, match="Unsupported"):
        claims.claims_to_session_info(FREJA_CLAIMS, method=ProofingMethods.SVIPE_ID)


def test_scopes_for_method() -> None:
    assert claims.scopes_for_method(ProofingMethods.FREJA) == [
        "openid",
        "https://id.oidc.se/scope/naturalPersonNumber",
        "https://id.oidc.se/scope/naturalPersonInfo",
    ]
    assert claims.scopes_for_method(ProofingMethods.EIDAS) == [
        "openid",
        "https://id.swedenconnect.se/scope/eidasNaturalPersonIdentity",
        "https://id.oidc.se/scope/naturalPersonInfo",
    ]


def test_freja_round_trip() -> None:
    session_info = claims.claims_to_session_info(FREJA_CLAIMS, method=ProofingMethods.FREJA)
    assert session_info is not None
    parsed = NinSessionInfo(**session_info)
    assert parsed.issuer == ISSUER
    assert parsed.authn_context == ACR
    assert parsed.authn_instant == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    assert parsed.attributes.nin == "197801012369"
    assert parsed.attributes.given_name == "Ulla"
    assert parsed.attributes.surname == "Alm"
    assert parsed.attributes.display_name == "Ulla Alm"
    assert parsed.attributes.date_of_birth.isoformat() == "1978-01-01"


def test_coordination_number_maps_to_nin() -> None:
    data = {k: v for k, v in FREJA_CLAIMS.items() if k != claims.CLAIM_PERSONAL_IDENTITY_NUMBER}
    data[claims.CLAIM_COORDINATION_NUMBER] = "197801612369"
    session_info = claims.claims_to_session_info(data, method=ProofingMethods.FREJA)
    assert session_info is not None
    assert NinSessionInfo(**session_info).attributes.nin == "197801612369"


def test_eidas_round_trip() -> None:
    data = {**EIDAS_CLAIMS, claims.CLAIM_MAPPED_PERSONAL_IDENTITY_NUMBER: "197801012369"}
    session_info = claims.claims_to_session_info(data, method=ProofingMethods.EIDAS)
    assert session_info is not None
    attrs = ForeignEidSessionInfo(**session_info).attributes
    assert attrs.prid == "XB:1bjrk7depnmhu7xn56kon3mlc9q1s0"
    assert attrs.prid_persistence == "B"
    assert attrs.eidas_person_identifier == "XB/SE/12345"
    assert attrs.country_code == "XB"
    assert attrs.transaction_identifier == "_a1b2c3"
    assert attrs.date_of_birth.isoformat() == "1964-12-31"
    assert attrs.mapped_personal_identity_number == "197801012369"


@pytest.mark.parametrize("missing", ["acr", "auth_time", "iss"])
def test_missing_required_claim_returns_none(missing: str) -> None:
    data = {k: v for k, v in FREJA_CLAIMS.items() if k != missing}
    assert claims.claims_to_session_info(data, method=ProofingMethods.FREJA) is None


def test_invalid_auth_time_returns_none() -> None:
    assert (
        claims.claims_to_session_info({**FREJA_CLAIMS, "auth_time": "yesterday"}, method=ProofingMethods.FREJA) is None
    )
    assert claims.claims_to_session_info({**FREJA_CLAIMS, "auth_time": True}, method=ProofingMethods.FREJA) is None


def test_missing_birthdate_is_omitted_and_reported() -> None:
    data = {k: v for k, v in FREJA_CLAIMS.items() if k != "birthdate"}
    session_info = claims.claims_to_session_info(data, method=ProofingMethods.FREJA)
    assert session_info is not None
    assert "dateOfBirth" not in session_info["ava"]
    with pytest.raises(ValidationError):
        NinSessionInfo(**session_info)

    method = ProofingMethodFreja(
        method=ProofingMethods.FREJA,
        framework=TrustFramework.SWECONN,
        finish_url="",
        idp=ISSUER,
        required_loa=["loa3"],
    )
    result = method.parse_session_info(session_info, backdoor=False)
    assert result.error == ProofingMsg.attribute_missing


def test_missing_eidas_attribute_reported() -> None:
    data = {k: v for k, v in EIDAS_CLAIMS.items() if k != "txn"}
    session_info = claims.claims_to_session_info(data, method=ProofingMethods.EIDAS)
    assert session_info is not None
    method = ProofingMethodEidas(
        method=ProofingMethods.EIDAS,
        framework=TrustFramework.SWECONN,
        finish_url="",
        idp=ISSUER,
        required_loa=["eidas-nf-sub"],
    )
    assert method.parse_session_info(session_info, backdoor=False).error == ProofingMsg.attribute_missing
