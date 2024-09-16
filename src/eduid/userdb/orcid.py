from __future__ import annotations

from typing import Any

from eduid.userdb.element import Element, ElementKey, VerifiedElement

__author__ = "lundberg"


class OidcIdToken(Element):
    """
    OpenID Connect ID token data
    """

    # Issuer identifier
    iss: str
    # Subject identifier
    sub: str
    # Audience(s)
    aud: list[str]
    # Expiration time
    exp: int
    # Time at which the JWT was issued. Its value is a JSON number representing
    # the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
    iat: int
    # Nonce used to associate a Client session with an ID Token, and to mitigate replay attacks.
    nonce: str | None = None
    # Time when the End-User authentication occurred.
    auth_time: int | None = None
    # Authentication Context Class Reference
    acr: str | None = None
    # Authentication Methods References
    amr: list[str] | None = None
    # Authorized party
    azp: str | None = None

    @property
    def key(self) -> ElementKey:
        """
        :return: Unique identifier
        """
        return ElementKey(f"{self.iss}{self.sub}")

    @classmethod
    def _from_dict_transform(cls: type[OidcIdToken], data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        data = super()._from_dict_transform(data)

        # these keys appear in the data sample in the eduid.userdb.tests.test_orcid module
        for key in ("at_hash", "family_name", "given_name", "jti"):
            if key in data:
                del data[key]

        return data


class OidcAuthorization(Element):
    """
    OpenID Connect Authorization data
    """

    access_token: str
    token_type: str
    id_token: OidcIdToken
    expires_in: int | None = None
    refresh_token: str | None = None

    @property
    def key(self) -> ElementKey:
        """
        :return: Unique identifier
        """
        return self.id_token.key

    @classmethod
    def _from_dict_transform(cls: type[OidcAuthorization], data: dict[str, Any]) -> dict[str, Any]:
        """ """
        data = super()._from_dict_transform(data)

        # these keys appear in the data sample in the eduid.userdb.tests.test_orcid module
        for key in ("name", "orcid", "scope"):
            if key in data:
                del data[key]

        # Parse ID token
        _id_token = data.pop("id_token")
        if isinstance(_id_token, dict):
            data["id_token"] = OidcIdToken.from_dict(_id_token)
        elif isinstance(_id_token, OidcIdToken):
            data["id_token"] = _id_token

        return data

    def _to_dict_transform(self, data: dict[str, Any]) -> dict[str, Any]:
        """ """
        data = super()._to_dict_transform(data)

        data["id_token"] = self.id_token.to_dict()
        return data


class Orcid(VerifiedElement):
    # User's ORCID
    id: str
    oidc_authz: OidcAuthorization
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None

    @property
    def key(self) -> ElementKey:
        """
        Unique id
        """
        return ElementKey(self.id)

    @classmethod
    def _from_dict_transform(cls: type[Orcid], data: dict[str, Any]) -> dict[str, Any]:
        """ """
        data = super()._from_dict_transform(data)

        # Parse ID token
        _oidc_authz = data.pop("oidc_authz")
        if isinstance(_oidc_authz, dict):
            data["oidc_authz"] = OidcAuthorization.from_dict(_oidc_authz)
        if isinstance(_oidc_authz, OidcAuthorization):
            data["oidc_authz"] = _oidc_authz

        return data

    def _to_dict_transform(self, data: dict[str, Any]) -> dict[str, Any]:
        """ """
        data["oidc_authz"] = self.oidc_authz.to_dict()

        _has_empty_name = "name" in data and data["name"] is None

        data = super()._to_dict_transform(data)

        if _has_empty_name:
            # Be bug-compatible with earlier code, to be able to release dataclass based
            # elements with confidence that nothing will change in the database. This can
            # be removed after a burn-in period.
            data["name"] = None

        return data
