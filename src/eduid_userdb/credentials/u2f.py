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
from __future__ import absolute_import

import copy
from hashlib import sha256
from six import string_types
from eduid_userdb.credentials import Credential
from eduid_userdb.exceptions import UserHasUnknownData, UserDBValueError

__author__ = 'ft'


class U2F(Credential):
    """
    U2F token authentication credential
    """

    def __init__(self,
                 version=None, keyhandle=None, public_key=None, app_id=None, attest_cert=None,
                 description=None,
                 application=None, created_ts=None, data=None,
                 raise_on_unknown=True):
        data_in = data
        data = copy.copy(data_in)  # to not modify callers data

        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(version = version,
                        keyhandle = keyhandle,
                        public_key = public_key,
                        app_id = app_id,
                        attest_cert = attest_cert,
                        description = description,
                        created_by = application,
                        created_ts = created_ts,
                        )

        Credential.__init__(self, data)
        self.version = data.pop('version')
        self.keyhandle = data.pop('keyhandle')
        self.public_key = data.pop('public_key')
        self.app_id = data.pop('app_id')
        self.attest_cert = data.pop('attest_cert', '')
        self.description = data.pop('description', '')

        leftovers = data.keys()
        if leftovers:
            if raise_on_unknown:
                raise UserHasUnknownData('U2F {!r} unknown data: {!r}'.format(
                    self.key, leftovers,
                ))
            # Just keep everything that is left as-is
            self._data.update(data)

    def __repr__(self):  # XXX was __repr__ what we settled on for Python3? Don't think so
        kh = self._data['keyhandle'][:8]
        if self.is_verified:
            return '<eduID {!s}: key_handle=\'{!s}...\', verified=True, proofing=({!r} v {!r})>'.format(
                self.__class__.__name__,
                kh,
                self.proofing_method,
                self.proofing_version
            )
        else:
            return '<eduID {!s}: key_handle=\'{!s}...\', verified=False>'.format(
                self.__class__.__name__, kh)


    @property
    def key(self):
        """
        Return the element that is used as key.
        """
        return 'sha256:' + sha256(self.keyhandle.encode('utf-8') +
                                  self.public_key.encode('utf-8')
                                  ).hexdigest()

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


def u2f_from_dict(data, raise_on_unknown=True):
    """
    Create an U2F instance from a dict.

    :param data: Credential parameters from database
    :param raise_on_unknown: Raise UserHasUnknownData if unrecognized data is encountered

    :type data: dict
    :type raise_on_unknown: bool
    :rtype: U2F
    """
    return U2F(data=data, raise_on_unknown=raise_on_unknown)
