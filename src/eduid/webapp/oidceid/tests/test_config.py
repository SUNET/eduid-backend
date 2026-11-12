from typing import Any

import pytest
from pydantic import ValidationError

from eduid.webapp.oidceid.settings.common import OidcEidConfig, SwedenConnectOidcClientConfig

OP1 = "https://op1.example.com"
OP2 = "https://op2.example.com"


def _provider(issuer: str) -> dict[str, Any]:
    return {"client_id": "cid", "issuer": issuer, "client_signing_key_path": "/tmp/key.pem"}


_CELERY = {"broker_url": "memory://"}


def _conf(**extra: Any) -> OidcEidConfig:
    return OidcEidConfig(mongo_uri="mongodb://localhost", celery=_CELERY, **extra)


def test_defaults() -> None:
    conf = _conf()
    assert conf.app_name == "oidceid"
    assert conf.providers == []
    assert conf.fetch_userinfo is False
    assert conf.method_authn_provider == {}
    provider = SwedenConnectOidcClientConfig(**_provider(OP1))
    assert provider.token_endpoint_auth_method == "private_key_jwt"
    assert provider.scopes == ["openid"]
    assert provider.acr_values == []


def test_idps_match_providers() -> None:
    conf = _conf(
        providers=[_provider(OP1), _provider(OP2)],
        freja_idp=OP1,
        foreign_identity_idp=OP2,
        bankid_idp=OP1,
        magic_cookie_idp=OP1,
        magic_cookie_bankid_idp=OP1,
        magic_cookie_foreign_id_idp=OP2,
    )
    assert conf.freja_idp == OP1


@pytest.mark.parametrize(
    "field",
    [
        "freja_idp",
        "foreign_identity_idp",
        "bankid_idp",
        "magic_cookie_idp",
        "magic_cookie_bankid_idp",
        "magic_cookie_foreign_id_idp",
    ],
)
def test_idp_not_matching_provider_rejected(field: str) -> None:
    with pytest.raises(ValidationError, match=field):
        _conf(providers=[_provider(OP1)], **{field: OP2})


def test_idp_without_providers_rejected() -> None:
    with pytest.raises(ValidationError):
        _conf(freja_idp=OP1)


def test_duplicate_issuers_rejected() -> None:
    with pytest.raises(ValidationError, match="unique"):
        _conf(providers=[_provider(OP1), _provider(OP1)])


def test_acr_values_rejected() -> None:
    with pytest.raises(ValidationError, match="acr_values must not be set"):
        SwedenConnectOidcClientConfig(**_provider(OP1), acr_values=["http://id.elegnamnden.se/loa/1.0/loa3"])


def test_fetch_userinfo_requires_signed_userinfo() -> None:
    with pytest.raises(ValidationError, match="fetch_userinfo requires userinfo_trust"):
        _conf(providers=[_provider(OP1)], fetch_userinfo=True)

    signed = _provider(OP1) | {"userinfo_trust": "typed", "userinfo_typ": "userinfo+jwt"}
    conf = _conf(providers=[signed], fetch_userinfo=True)
    assert conf.fetch_userinfo is True


def test_require_iss_is_default() -> None:
    assert SwedenConnectOidcClientConfig(**_provider(OP1)).require_iss is True
    assert SwedenConnectOidcClientConfig(**_provider(OP1), require_iss=False).require_iss is False
