# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Type

from eduid_userdb.element import Element, VerifiedElement

__author__ = 'lundberg'


@dataclass
class _OidcIdTokenRequired:
    """
    This is used to order the required args for OidcIdToken
    before the optional args for Element
    """

    # Issuer identifier
    iss: str
    # Subject identifier
    sub: str
    # Audience(s)
    aud: List[str]
    # Expiration time
    exp: int
    # Time at which the JWT was issued. Its value is a JSON number representing
    # the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
    iat: int


@dataclass
class OidcIdToken(Element, _OidcIdTokenRequired):
    """
    OpenID Connect ID token data
    """

    # Nonce used to associate a Client session with an ID Token, and to mitigate replay attacks.
    nonce: Optional[str] = None
    # Time when the End-User authentication occurred.
    auth_time: Optional[int] = None
    # Authentication Context Class Reference
    acr: Optional[str] = None
    # Authentication Methods References
    amr: Optional[List[str]] = None
    # Authorized party
    azp: Optional[str] = None

    @property
    def key(self) -> str:
        """
        :return: Unique identifier
        """
        return f'{self.iss}{self.sub}'

    @classmethod
    def _data_in_transforms(cls: Type[OidcIdToken], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        data = super()._data_in_transforms(data)

        # these keys appear in the data sample in the eduid_userdb.tests.test_orcid module
        for key in ('at_hash', 'family_name', 'given_name', 'jti'):
            if key in data:
                del data[key]

        return data


@dataclass
class _OidcAuthorizationRequired:
    """
    This is used to order the required args for OidcAuthorization
    before the optional args for Element
    """

    access_token: str
    token_type: str
    id_token: OidcIdToken


@dataclass
class OidcAuthorization(Element, _OidcAuthorizationRequired):
    """
    OpenID Connect Authorization data
    """

    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None

    @property
    def key(self) -> str:
        """
        :return: Unique identifier
        """
        return self.id_token.key

    @classmethod
    def _data_in_transforms(cls: Type[OidcAuthorization], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        """
        data = super()._data_in_transforms(data)

        # these keys appear in the data sample in the eduid_userdb.tests.test_orcid module
        for key in ('name', 'orcid', 'scope'):
            if key in data:
                del data[key]

        # Parse ID token
        _id_token = data.pop('id_token')
        if isinstance(_id_token, dict):
            data['id_token'] = OidcIdToken.from_dict(_id_token)
        elif isinstance(_id_token, OidcIdToken):
            data['id_token'] = _id_token

        return data

    def _data_out_transforms(self, data: Dict[str, Any], old_userdb_format: bool = False) -> Dict[str, Any]:
        """
        """
        data = super()._data_out_transforms(data, old_userdb_format)

        data['id_token'] = self.id_token.to_dict()
        return data


@dataclass
class _OrcidRequired:
    """
    Required fields for Orcid
    """

    # User's ORCID
    id: str
    oidc_authz: OidcAuthorization


@dataclass
class Orcid(VerifiedElement, _OrcidRequired):
    """
    """

    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None

    @property
    def key(self) -> str:
        """
        Unique id
        """
        return self.id

    @classmethod
    def _data_in_transforms(cls: Type[Orcid], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        """
        data = super()._data_in_transforms(data)

        # Parse ID token
        _oidc_authz = data.pop('oidc_authz')
        if isinstance(_oidc_authz, dict):
            data['oidc_authz'] = OidcAuthorization.from_dict(_oidc_authz)
        if isinstance(_oidc_authz, OidcAuthorization):
            data['oidc_authz'] = _oidc_authz

        return data

    def _data_out_transforms(self, data: Dict[str, Any], old_userdb_format: bool = False) -> Dict[str, Any]:
        """
        """
        data = super()._data_out_transforms(data, old_userdb_format)

        data['oidc_authz'] = self.oidc_authz.to_dict()
        return data
