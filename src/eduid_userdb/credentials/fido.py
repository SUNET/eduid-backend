# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#
from __future__ import annotations

import copy
from datetime import datetime
from hashlib import sha256
from typing import Any, Dict, Optional, Type, Union

from six import string_types

from eduid_userdb.credentials import Credential
from eduid_userdb.exceptions import UserDBValueError, UserHasUnknownData

__author__ = 'ft'


class FidoCredential(Credential):
    """
    Token authentication credential
    """

    def __init__(self, data: Dict[str, Any], called_directly: bool = True):

        super().__init__(data, called_directly=called_directly)
        self.keyhandle = data.pop('keyhandle')
        self.app_id = data.pop('app_id')
        self.description = data.pop('description', '')

    def check_unknown_data(self, data: Dict[str, Any]):
        """
        called when an instance of a subclass is created with `raise_on_unknown`
        """
        leftovers = data.keys()
        if leftovers:
            raise UserHasUnknownData(f'{self.__class__.__name__} {self.key} unknown data: {leftovers}')

    @property
    def keyhandle(self):
        """
        This is the server side reference to the U2F token used.

        :return: U2F keyhandle.
        :rtype: str
        """
        return self._data['keyhandle']

    @keyhandle.setter
    def keyhandle(self, value):
        """
        :param value: U2F keyhandle.
        :type value: str
        """
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'keyhandle': {!r}".format(value))
        self._data['keyhandle'] = value

    @property
    def app_id(self):
        """
        The U2F app_id used when creating this credential.

        :return: U2F app_id
        :rtype: str
        """
        return self._data['app_id']

    @app_id.setter
    def app_id(self, value):
        """
        :param value: U2F app_id.
        :type value: str
        """
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'app_id': {!r}".format(value))
        self._data['app_id'] = value

    @property
    def description(self):
        """
        User description/name of this token.

        :return: description
        :rtype: str
        """
        return self._data['description']

    @description.setter
    def description(self, value):
        """
        :param value: U2F description.
        :type value: str
        """
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'description': {!r}".format(value))
        self._data['description'] = value


class U2F(FidoCredential):
    """
    U2F token authentication credential
    """

    def __init__(
        self,
        version: Optional[str] = None,
        keyhandle: Optional[str] = None,
        public_key: Optional[str] = None,
        app_id: Optional[str] = None,
        attest_cert: Optional[str] = None,
        description: Optional[str] = None,
        application: Optional[str] = None,
        created_ts: Optional[Union[datetime, bool]] = None,
        data: Optional[Dict[str, Any]] = None,
        raise_on_unknown: bool = True,
        called_directly: bool = True,
    ):
        data_in = data
        data = copy.copy(data_in)  # to not modify callers data

        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(
                version=version,
                keyhandle=keyhandle,
                public_key=public_key,
                app_id=app_id,
                attest_cert=attest_cert,
                description=description,
                created_by=application,
                created_ts=created_ts,
            )
        elif 'created_ts' not in data:
            data['created_ts'] = True

        super().__init__(data, called_directly=called_directly)

        self.version = data.pop('version')
        self.public_key = data.pop('public_key')
        self.attest_cert = data.pop('attest_cert', '')

        if raise_on_unknown:
            self.check_unknown_data(data)

        # Just keep everything that is left as-is
        self._data.update(data)

    @classmethod
    def from_dict(cls: Type[U2F], data: Dict[str, Any], raise_on_unknown: bool = True) -> U2F:
        """
        Construct U2F credential from a data dict.
        """
        return cls(data=data, called_directly=False, raise_on_unknown=raise_on_unknown)

    @property
    def key(self):
        """
        Return the element that is used as key.
        """
        return 'sha256:' + sha256(self.keyhandle.encode('utf-8') + self.public_key.encode('utf-8')).hexdigest()

    @property
    def version(self):
        """
        This is the U2F version used by this token.

        :return: U2F version.
        :rtype: str
        """
        return self._data['version']

    @version.setter
    def version(self, value):
        """
        :param value: U2F version. E.g. 'U2F_V2'.
        :type value: str
        """
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'version': {!r}".format(value))
        self._data['version'] = value

    @property
    def attest_cert(self):
        """
        The U2F attest_cert from the credential.

        We should probably refine what we store here later on, but for now we just
        store the whole certificate.

        :return: U2F attest_cert
        :rtype: str
        """
        return self._data['attest_cert']

    @attest_cert.setter
    def attest_cert(self, value):
        """
        :param value: U2F attest_cert.
        :type value: str
        """
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'attest_cert': {!r}".format(value))
        self._data['attest_cert'] = value

    @property
    def public_key(self):
        """
        This is the public key of the U2F token.

        :return: U2F public_key.
        :rtype: str
        """
        return self._data['public_key']

    @public_key.setter
    def public_key(self, value):
        """
        :param value: U2F public_key.
        :type value: str
        """
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'public_key': {!r}".format(value))
        self._data['public_key'] = value


def u2f_from_dict(data, raise_on_unknown=True):
    """
    Create an U2F instance from a dict.

    :param data: Credential parameters from database
    :param raise_on_unknown: Raise UserHasUnknownData if unrecognized data is encountered

    :type data: dict
    :type raise_on_unknown: bool
    :rtype: U2F
    """
    return U2F.from_dict(data, raise_on_unknown=raise_on_unknown)


class Webauthn(FidoCredential):
    """
    Webauthn token authentication credential
    """

    def __init__(
        self,
        keyhandle: Optional[str] = None,
        credential_data: Optional[str] = None,
        app_id: Optional[str] = None,
        attest_obj: Optional[str] = None,
        description: Optional[str] = None,
        application: Optional[str] = None,
        created_ts: Optional[Union[datetime, bool]] = None,
        data: Optional[Dict[str, Any]] = None,
        raise_on_unknown: bool = True,
        called_directly: bool = True,
    ):
        data_in = data
        data = copy.copy(data_in)  # to not modify callers data

        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(
                keyhandle=keyhandle,
                credential_data=credential_data,
                app_id=app_id,
                attest_obj=attest_obj,
                description=description,
                created_by=application,
                created_ts=created_ts,
            )
        elif 'created_ts' not in data:
            data['created_ts'] = True

        super().__init__(data, called_directly=called_directly)

        self.attest_obj = data.pop('attest_obj', '')
        self.credential_data = data.pop('credential_data', '')

        if raise_on_unknown:
            self.check_unknown_data(data)

        # Just keep everything that is left as-is
        self._data.update(data)

    @classmethod
    def from_dict(cls: Type[Webauthn], data: Dict[str, Any], raise_on_unknown: bool = True) -> Webauthn:
        """
        Construct Webauthn credential from a data dict.
        """
        return cls(data=data, called_directly=False, raise_on_unknown=raise_on_unknown)

    @property
    def key(self):
        """
        Return the element that is used as key.
        """
        return 'sha256:' + sha256(self.keyhandle.encode('utf-8') + self.credential_data.encode('utf-8')).hexdigest()

    @property
    def attest_obj(self):
        """
        The Webauthn attestation object for the credential.

        We should probably refine what we store here later on, but for now we just
        store the whole object.

        :return: Webauthn attest_obj
        :rtype: str
        """
        return self._data['attest_obj']

    @attest_obj.setter
    def attest_obj(self, value):
        """
        :param value: Webauthn attest_obj.
        :type value: str
        """
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'attest_obj': {!r}".format(value))
        self._data['attest_obj'] = value

    @property
    def credential_data(self):
        """
        This is the credential data of the Webauthn token.

        :return: Webauthn credential data
        :rtype: str
        """
        return self._data['credential_data']

    @credential_data.setter
    def credential_data(self, value):
        """
        :param value: Webauthn credential data
        :type value: str
        """
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'credential_data': {!r}".format(value))
        self._data['credential_data'] = value


def webauthn_from_dict(data, raise_on_unknown=True):
    """
    Create an Webauthn instance from a dict.

    :param data: Credential parameters from database
    :param raise_on_unknown: Raise UserHasUnknownData if unrecognized data is encountered

    :type data: dict
    :type raise_on_unknown: bool
    :rtype: Webauthn
    """
    return Webauthn.from_dict(data, raise_on_unknown=raise_on_unknown)
