# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass, asdict
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
    # Expiration time
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

    @classmethod
    def massage_data(
        cls: Type[OidcIdToken], data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        """
        data = super().massage_data(data)

        for key in ('at_hash', 'family_name', 'given_name', 'jti'):
            if key in data:
                del data[key]

        return data

    @property
    def key(self):
        """
        :return: Unique identifier
        :rtype: six.string_types
        """
        return '{}{}'.format(self.iss, self.sub)


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

    @classmethod
    def massage_data(
        cls: Type[OidcAuthorization], data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        """
        data = super().massage_data(data)

        # Parse ID token
        _id_token = data.pop('id_token')
        if isinstance(_id_token, dict):
            data['id_token'] = OidcIdToken.from_dict(_id_token)
        elif isinstance(_id_token, OidcIdToken):
            data['id_token'] = _id_token

        for key in ('name', 'orcid', 'scope'):
            if key in data:
                del data[key]

        return data

    @property
    def key(self):
        """
        :return: Unique identifier
        :rtype: six.string_types
        """
        return self.id_token.key

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert OidcAuthorization to a dict
        """
        data = asdict(self)
        data['id_token'] = self.id_token.to_dict()
        return data


@dataclass
class _OrcidRequired:
    """
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

    @classmethod
    def massage_data(cls: Type[Orcid], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Construct user from a data dict.
        """
        data = super().massage_data(data)

        # Parse ID token
        _oidc_authz = data.pop('oidc_authz')
        if isinstance(_oidc_authz, dict):
            data['oidc_authz'] = OidcAuthorization.from_dict(_oidc_authz)
        if isinstance(_oidc_authz, OidcAuthorization):
            data['oidc_authz'] = _oidc_authz

        return data

    @property
    def key(self):
        """
        Unique id
        """
        return self.id

    def to_dict(self):
        """
        Convert Element to a dict, that can be used to reconstruct the
        Element later.
        """
        data = asdict(self)
        data['oidc_authz'] = self.oidc_authz.to_dict()
        return data
