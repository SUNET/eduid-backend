# -*- coding: utf-8 -*-

from __future__ import absolute_import

import copy
from typing import Any, Dict, Optional, Type

from six import string_types

from eduid_userdb.element import Element, VerifiedElement
from eduid_userdb.exceptions import UserDBValueError, UserHasUnknownData

__author__ = 'lundberg'


class OidcElement(Element):
    def __init__(
        self, data: Optional[Dict[str, Any]] = None, raise_on_unknown: bool = True, called_directly: bool = True,
    ):
        raise NotImplementedError()

    @classmethod
    def from_dict(cls: Type['OidcElement'], data: Dict[str, Any], raise_on_unknown: bool = True) -> 'OidcElement':
        """
        Construct user from a data dict.
        """
        return cls(data=data, called_directly=False, raise_on_unknown=raise_on_unknown)


class OidcIdToken(OidcElement):
    """
    OpenID Connect ID token data
    """

    def __init__(
        self,
        iss=None,
        sub=None,
        aud=None,
        exp=None,
        iat=None,
        nonce=None,
        auth_time=None,
        acr=None,
        amr=None,
        azp=None,
        application=None,
        created_ts=None,
        data=None,
        raise_on_unknown=True,
        called_directly=True,
    ):
        data_in = data
        data = copy.deepcopy(data_in)  # to not modify callers data

        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(
                iss=iss,
                sub=sub,
                aud=aud,
                exp=exp,
                iat=iat,
                nonce=nonce,
                auth_time=auth_time,
                acr=acr,
                amr=amr,
                azp=azp,
                created_by=application,
                created_ts=created_ts,
            )
        elif 'created_ts' not in data:
            data['created_ts'] = True

        Element.__init__(self, data, called_directly=called_directly)
        self.iss = data.pop('iss')
        self.sub = data.pop('sub')
        self.aud = data.pop('aud')
        self.exp = data.pop('exp')
        self.iat = data.pop('iat')
        self.nonce = data.pop('nonce', None)
        self.auth_time = data.pop('auth_time', None)
        self.acr = data.pop('acr', None)
        self.amr = data.pop('amr', None)
        self.azp = data.pop('azp', None)

        if raise_on_unknown and data:
            raise UserHasUnknownData('{!s} has unknown data: {!r}'.format(self.__class__.__name__, data.keys()))

    @property
    def key(self):
        """
        :return: Unique identifier
        :rtype: six.string_types
        """
        return '{}{}'.format(self.iss, self.sub)

    # -----------------------------------------------------------------
    @property
    def iss(self):
        """
        Issuer identifier

        :return: Issuer url
        :rtype: six.string_types
        """
        return self._data['iss']

    @iss.setter
    def iss(self, value):
        """
        :param value: Issuer
        :type value: six.string_types
        """
        if not value or not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'iss': {!r}".format(value))
        self._data['iss'] = value

    # -----------------------------------------------------------------
    @property
    def sub(self):
        """
        Subject identifier

        :return: subject id
        :rtype: six.string_types
        """
        return self._data['sub']

    @sub.setter
    def sub(self, value):
        """
        :param value: Subject id
        :type value: six.string_types
        """
        if not value or not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'sub': {!r}".format(value))
        self._data['sub'] = value

    # -----------------------------------------------------------------
    @property
    def aud(self):
        """
        Audience(s)

        :return: audience list
        :rtype: list
        """
        return self._data['aud']

    @aud.setter
    def aud(self, value):
        """
        :param value: audience list
        :type value: list
        """
        if not isinstance(value, list):
            raise UserDBValueError("Invalid 'aud': {!r}".format(value))
        self._data['aud'] = value

    # -----------------------------------------------------------------
    @property
    def exp(self):
        """
        Expiration time

        :return: expiration time
        :rtype: int
        """
        return self._data['exp']

    @exp.setter
    def exp(self, value):
        """
        :param value: expiration time
        :type value: int
        """
        if not isinstance(value, int):
            raise UserDBValueError("Invalid 'exp': {!r}".format(value))
        self._data['exp'] = value

    # -----------------------------------------------------------------
    @property
    def iat(self):
        """
        Expiration time

        :return: expiration time
        :rtype: int
        """
        return self._data['iat']

    @iat.setter
    def iat(self, value):
        """
        :param value: expiration time
        :type value: int
        """
        if not isinstance(value, int):
            raise UserDBValueError("Invalid 'iat': {!r}".format(value))
        self._data['iat'] = value

    # -----------------------------------------------------------------
    @property
    def nonce(self):
        """
        Nonce used to associate a Client session with an ID Token, and to mitigate replay attacks.

        :return: nonce
        :rtype: six.string_types
        """
        return self._data.get('nonce')

    @nonce.setter
    def nonce(self, value):
        """
        :param value: nonce
        :type value: six.string_types | None
        """
        if value is not None:  # No op for value None
            if not isinstance(value, string_types):
                raise UserDBValueError("Invalid 'nonce': {!r}".format(value))
            self._data['nonce'] = value

    # -----------------------------------------------------------------
    @property
    def auth_time(self):
        """
        Time when the End-User authentication occurred.

        :return: auth time
        :rtype: int
        """
        return self._data.get('auth_time')

    @auth_time.setter
    def auth_time(self, value):
        """
        :param value: auth time
        :type value: int
        """
        if value is not None:  # No op for value None
            if not isinstance(value, int):
                raise UserDBValueError("Invalid 'auth_time': {!r}".format(value))
            self._data['auth_time'] = value

    # -----------------------------------------------------------------
    @property
    def acr(self):
        """
        Authentication Context Class Reference

        :return: acr
        :rtype: six.string_types
        """
        return self._data.get('acr')

    @acr.setter
    def acr(self, value):
        """
        :param value: acr
        :type value: six.string_types
        """
        if value is not None:  # No op for value None
            if not isinstance(value, string_types):
                raise UserDBValueError("Invalid 'acr': {!r}".format(value))
            self._data['acr'] = value

    # -----------------------------------------------------------------
    @property
    def amr(self):
        """
        Authentication Methods References

        :return: nin number.
        :rtype: list
        """
        return self._data.get('amr')

    @amr.setter
    def amr(self, value):
        """
        :param value: nin number.
        :type value: list
        """
        if value is not None:  # No op for value None
            if not isinstance(value, list):
                raise UserDBValueError("Invalid 'amr': {!r}".format(value))
            self._data['amr'] = value

    # -----------------------------------------------------------------
    @property
    def azp(self):
        """
        Authorized party

        :return: acr
        :rtype: six.string_types
        """
        return self._data.get('azp')

    @azp.setter
    def azp(self, value):
        """
        :param value: acr
        :type value: six.string_types
        """
        if value is not None:  # No op for value None
            if not isinstance(value, string_types):
                raise UserDBValueError("Invalid 'azp': {!r}".format(value))
            self._data['azp'] = value


class OidcAuthorization(OidcElement):
    """
    OpenID Connect Authorization data
    """

    def __init__(
        self,
        access_token=None,
        token_type=None,
        id_token=None,
        expires_in=None,
        refresh_token=None,
        application=None,
        created_ts=None,
        data=None,
        raise_on_unknown=True,
        called_directly=True,
    ):
        data_in = data
        data = copy.deepcopy(data_in)  # to not modify callers data

        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(
                access_token=access_token,
                token_type=token_type,
                id_token=id_token,
                expires_in=expires_in,
                refresh_token=refresh_token,
                created_by=application,
                created_ts=created_ts,
            )
        elif 'created_ts' not in data:
            data['created_ts'] = True

        Element.__init__(self, data, called_directly=called_directly)
        self.access_token = data.pop('access_token')
        self.token_type = data.pop('token_type')
        self.expires_in = data.pop('expires_in')
        self.refresh_token = data.pop('refresh_token')

        # Parse ID token
        _id_token = data.pop('id_token')
        if isinstance(_id_token, dict):
            self.id_token = OidcIdToken.from_dict(_id_token, raise_on_unknown=raise_on_unknown)
        if isinstance(_id_token, OidcIdToken):
            self.id_token = _id_token

        if raise_on_unknown and data:
            raise UserHasUnknownData('{!s} has unknown data: {!r}'.format(self.__class__.__name__, data.keys()))

    @property
    def key(self):
        """
        :return: Unique identifier
        :rtype: six.string_types
        """
        return self.id_token.key

    # -----------------------------------------------------------------
    @property
    def access_token(self):
        """
        Access token

        :return: access token
        :rtype: six.string_types
        """
        return self._data['access_token']

    @access_token.setter
    def access_token(self, value):
        """
        :param value: Access token
        :type value: six.string_types
        """
        if not value or not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'access_token': {!r}".format(value))
        self._data['access_token'] = value

    # -----------------------------------------------------------------
    @property
    def token_type(self):
        """
        Token type

        :return: token type
        :rtype: six.string_types
        """
        return self._data['sub']

    @token_type.setter
    def token_type(self, value):
        """
        :param value: token type
        :type value: six.string_types
        """
        if not value or not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'token_type': {!r}".format(value))
        self._data['token_type'] = value.lower()  # Case insensitive

    # -----------------------------------------------------------------
    @property
    def id_token(self):
        """
        ID Token

        :return: id token
        :rtype: six.string_types
        """
        return self._data['id_token']

    @id_token.setter
    def id_token(self, value):
        """
        :param value: id token
        :type value: six.string_types
        """
        if not isinstance(value, OidcIdToken):
            raise UserDBValueError("Invalid 'id_token': {!r}".format(value))
        self._data['id_token'] = value

    # -----------------------------------------------------------------
    @property
    def expires_in(self):
        """
        The lifetime in seconds of the access token.

        :return: expires in
        :rtype: int
        """
        return self._data.get('expires_in')

    @expires_in.setter
    def expires_in(self, value):
        """
        :param value: expires in
        :type value: int
        """
        if value is not None:  # No op for value None
            if not isinstance(value, int):
                raise UserDBValueError("Invalid 'expires_in': {!r}".format(value))
            self._data['expires_in'] = value

    # -----------------------------------------------------------------
    @property
    def refresh_token(self):
        """
        Refresh token

        :return: refresh token
        :rtype: six.string_types
        """
        return self._data.get('refresh_token')

    @refresh_token.setter
    def refresh_token(self, value):
        """
        :param value: refresh token
        :type value: six.string_types
        """
        if value is not None:  # No op for value None
            if not isinstance(value, string_types):
                raise UserDBValueError("Invalid 'refresh_token': {!r}".format(value))
            self._data['refresh_token'] = value

    def to_dict(self, old_userdb_format=False):
        """
        Convert OidcAuthorization to a dict

        :param old_userdb_format: Set to True to get data back in legacy format.
        :type old_userdb_format: bool

        :return data dict
        :rtype dict
        """
        data = copy.deepcopy(self._data)
        data['id_token'] = self.id_token.to_dict()
        return data


class Orcid(VerifiedElement):
    """
    :param data: Orcid parameters from database
    :param raise_on_unknown: Raise exception on unknown values in `data' or not.

    :type data: dict
    :type raise_on_unknown: bool
    """

    def __init__(
        self,
        id=None,
        name=None,
        given_name=None,
        family_name=None,
        oidc_authz=None,
        application=None,
        verified=False,
        created_ts=None,
        data=None,
        raise_on_unknown=True,
        called_directly=True,
    ):
        data_in = data
        data = copy.deepcopy(data_in)  # to not modify callers data

        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(
                id=id,
                name=name,
                given_name=given_name,
                family_name=family_name,
                oidc_authz=oidc_authz,
                created_by=application,
                created_ts=created_ts,
                verified=verified,
            )
        elif 'created_ts' not in data:
            data['created_ts'] = True

        VerifiedElement.__init__(self, data, called_directly=called_directly)
        self.id = data.pop('id')
        self.name = data.pop('name', None)
        self.given_name = data.pop('given_name', None)
        self.family_name = data.pop('family_name', None)

        # Parse ID token
        _oidc_authz = data.pop('oidc_authz')
        if isinstance(_oidc_authz, dict):
            self.oidc_authz = OidcAuthorization.from_dict(_oidc_authz)
        if isinstance(_oidc_authz, OidcAuthorization):
            self.oidc_authz = _oidc_authz

        if raise_on_unknown and data:
            raise UserHasUnknownData('{!s} has unknown data: {!r}'.format(self.__class__.__name__, data.keys()))

    @classmethod
    def from_dict(cls: Type['Orcid'], data: Dict[str, Any], raise_on_unknown: bool = True) -> 'Orcid':
        """
        Construct user from a data dict.
        """
        return cls(data=data, called_directly=False, raise_on_unknown=raise_on_unknown)

    # -----------------------------------------------------------------
    @property
    def key(self):
        """
        Unique id
        """
        return self.id

    # -----------------------------------------------------------------
    @property
    def id(self):
        """
        Users ORCID

        :return: orcid
        :rtype: six.string_types
        """
        return self._data['id']

    @id.setter
    def id(self, value):
        """
        :param value: ORCID
        :type value: str | unicode
        """
        if not value or not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'id': {!r}".format(value))
        self._data['id'] = str(value.lower())  # Case insensitive

    # -----------------------------------------------------------------
    @property
    def name(self):
        """
        Users name

        :return: name
        :rtype: six.string_types
        """
        return self._data['name']

    @name.setter
    def name(self, value):
        """
        :param value: name
        :type value: str | unicode | None
        """
        if value is not None and not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'name': {!r}".format(value))
        self._data['name'] = value

    # -----------------------------------------------------------------
    @property
    def given_name(self):
        """
        Users given_name

        :return: given name
        :rtype: six.string_types
        """
        return self._data['given_name']

    @given_name.setter
    def given_name(self, value):
        """
        :param value: given name
        :type value: str | unicode | None
        """
        if value is not None and not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'given_name': {!r}".format(value))
        self._data['given_name'] = value

    # -----------------------------------------------------------------
    @property
    def family_name(self):
        """
        Users family name

        :return: family name
        :rtype: six.string_types
        """
        return self._data['family_name']

    @family_name.setter
    def family_name(self, value):
        """
        :param value: family name
        :type value: str | unicode | None
        """
        if value is not None and not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'family_name': {!r}".format(value))
        self._data['family_name'] = value

    # -----------------------------------------------------------------
    @property
    def oidc_authz(self):
        """
        Users ORCID OIDC authorization data

        :return: oidc authorization data
        :rtype: OidcAuthorization
        """
        return self._data['oidc_authz']

    @oidc_authz.setter
    def oidc_authz(self, value):
        """
        :param value: oidc authorization data
        :type value: OidcAuthorization
        """
        if not isinstance(value, OidcAuthorization):
            raise UserDBValueError("Invalid 'oidc_authz': {!r}".format(value))
        self._data['oidc_authz'] = value

    # -----------------------------------------------------------------
    def to_dict(self, old_userdb_format=False):
        """
        Convert Element to a dict, that can be used to reconstruct the
        Element later.

        :param old_userdb_format: Set to True to get data back in legacy format.
        :type old_userdb_format: bool
        """
        data = copy.deepcopy(self._data)
        data['oidc_authz'] = self.oidc_authz.to_dict()
        return data
