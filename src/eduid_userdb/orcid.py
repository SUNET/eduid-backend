# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Dict, List, Optional, Type

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
    # What is this?
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

    name_mapping: ClassVar[Dict[str, str]] = {'application': 'created_by', 'at_hash': '', 'family_name': '', 'given_name': '', 'jti': ''}

    @property
    def key(self) -> str:
        """
        :return: Unique identifier
        """
        return f'{self.iss}{self.sub}'


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

    # XXX the data samples in the tests in test_orcid provide these keys,
    # and here we remove them to avoid a TypeError.
    name_mapping: ClassVar[Dict[str, str]] = {'name': '', 'orcid': '', 'scope': ''}

    @property
    def key(self) -> str:
        """
        :return: Unique identifier
        """
        return self.id_token.key

    @classmethod
    def data_in_transforms(
        cls: Type[OidcAuthorization], data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        """
        data = super().data_in_transforms(data)

        # Parse ID token
        _id_token = data.pop('id_token')
        if isinstance(_id_token, dict):
            data['id_token'] = OidcIdToken.from_dict(_id_token)
        elif isinstance(_id_token, OidcIdToken):
            data['id_token'] = _id_token

        return data

    def data_out_transforms(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        """
        data = super().data_out_transforms(data)

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

    name_mapping: ClassVar[Dict[str, str]] = {'application': 'created_by'}

    @property
    def key(self) -> str:
        """
        Unique id
        """
        return self.id

    @classmethod
    def data_in_transforms(cls: Type[Orcid], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        """
        data = super().data_in_transforms(data)

        # Parse ID token
        _oidc_authz = data.pop('oidc_authz')
        if isinstance(_oidc_authz, dict):
            data['oidc_authz'] = OidcAuthorization.from_dict(_oidc_authz)
        if isinstance(_oidc_authz, OidcAuthorization):
            data['oidc_authz'] = _oidc_authz

        return data

    def data_out_transforms(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        """
        data = super().data_out_transforms(data)

        data['oidc_authz'] = self.oidc_authz.to_dict()
        return data
