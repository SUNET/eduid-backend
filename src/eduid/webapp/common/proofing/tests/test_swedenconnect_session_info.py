from typing import Any

import pytest
from pydantic import ValidationError

from eduid.webapp.common.proofing.swedenconnect.session_info import (
    BankIDSessionInfo,
    ForeignEidSessionInfo,
    NinSessionInfo,
)

_ISSUER = "https://idp.example.com"
_AUTHN_INFO: list[tuple[str, list[str], str]] = [("http://id.elegnamnden.se/loa/1.0/loa3", [], "2026-01-01T12:00:00Z")]

_FREJA_AVA = {
    "personalIdentityNumber": ["197801012369"],
    "givenName": ["Ulla"],
    "sn": ["Alm"],
    "dateOfBirth": ["1978-01-01"],
}
_BANKID_AVA = {
    "personalIdentityNumber": ["197801012369"],
    "givenName": ["Ulla"],
    "sn": ["Alm"],
    "transactionIdentifier": ["bf5d125b"],
    "authContextParams": ["uidId=abc;"],
}


def _without(ava: dict[str, Any], key: str) -> dict[str, Any]:
    return {k: v for k, v in ava.items() if k != key}


def test_valid_assertions_parse() -> None:
    NinSessionInfo(issuer=_ISSUER, authn_info=_AUTHN_INFO, ava=_FREJA_AVA)
    BankIDSessionInfo(issuer=_ISSUER, authn_info=_AUTHN_INFO, ava=_BANKID_AVA)


def test_nin_requires_date_of_birth() -> None:
    ava = _without(_FREJA_AVA, "dateOfBirth")
    with pytest.raises(ValidationError):
        NinSessionInfo(issuer=_ISSUER, authn_info=_AUTHN_INFO, ava=ava)


def test_bankid_requires_auth_context_params() -> None:
    ava = _without(_BANKID_AVA, "authContextParams")
    with pytest.raises(ValidationError):
        BankIDSessionInfo(issuer=_ISSUER, authn_info=_AUTHN_INFO, ava=ava)


def test_freja_assertion_is_not_bankid() -> None:
    with pytest.raises(ValidationError):
        BankIDSessionInfo(issuer=_ISSUER, authn_info=_AUTHN_INFO, ava=_FREJA_AVA)


def test_bankid_assertion_is_not_nin() -> None:
    with pytest.raises(ValidationError):
        NinSessionInfo(issuer=_ISSUER, authn_info=_AUTHN_INFO, ava=_BANKID_AVA)


def test_bankid_assertion_is_not_foreign_eid() -> None:
    with pytest.raises(ValidationError):
        ForeignEidSessionInfo(issuer=_ISSUER, authn_info=_AUTHN_INFO, ava=_BANKID_AVA)
