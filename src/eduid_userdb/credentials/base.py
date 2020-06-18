# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 SUNET
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

from six import string_types
from typing import Any, Dict

from eduid_userdb.element import VerifiedElement
from eduid_userdb.exceptions import UserDBValueError

__author__ = 'ft'


class Credential(VerifiedElement):
    """
    Base class for credentials.

    Adds 'proofing_method' to VerifiedElement. Maybe that could benefit the
    main VerifiedElement, but after a short discussion we chose to add it
    only for credentials until we know we want it for other types of verifed
    elements too.
    """

    def __init__(self, data: Dict[str, Any], called_directly: bool = True):
        super(Credential, self).__init__(data, called_directly=called_directly)

        self.proofing_method = data.pop('proofing_method', None)
        self.proofing_version = data.pop('proofing_version', None)

    def __str__(self):
        shortkey = self.key[:12]
        if self.is_verified:
            return '<eduID {!s}(key=\'{!s}...\'): verified=True, proofing=({!r} v {!r})>'.format(
                self.__class__.__name__, shortkey, self.proofing_method, self.proofing_version
            )
        else:
            return '<eduID {!s}(key=\'{!s}...\'): verified=False>'.format(self.__class__.__name__, shortkey)

    # -----------------------------------------------------------------
    @property
    def proofing_method(self):
        """
        :return: Name of proofing process used to verify this credential.
        :rtype: string_types | None
        """
        return self._data['proofing_method']

    @proofing_method.setter
    def proofing_method(self, value):
        """
        :param value: Name of proofing process used
        :type value: string_types | None
        """
        if not isinstance(value, string_types) and value is not None:
            raise UserDBValueError("Invalid 'proofing_method': {!r}".format(value))
        self._data['proofing_method'] = value

    # -----------------------------------------------------------------
    @property
    def proofing_version(self):
        """
        :return: Name of proofing process used to verify this credential.
        :rtype: string_types | None
        """
        return self._data['proofing_version']

    @proofing_version.setter
    def proofing_version(self, value):
        """
        :param value: Name of proofing process used
        :type value: string_types | None
        """
        if not isinstance(value, string_types) and value is not None:
            raise UserDBValueError("Invalid 'proofing_version': {!r}".format(value))
        self._data['proofing_version'] = value

    def to_dict(self, old_userdb_format=False):
        res = super(Credential, self).to_dict(old_userdb_format=old_userdb_format)
        if res.get('verified') is True:
            # suppress method/version None to avoid messing up test cases unnecessarily
            if 'proofing_method' in res and res['proofing_method'] is None:
                del res['proofing_method']
            if 'proofing_version' in res and res['proofing_version'] is None:
                del res['proofing_version']
        elif res.get('verified') is False:
            del res['verified']
            # Make sure we never store proofing info for un-verified credentials
            if 'proofing_method' in res:
                del res['proofing_method']
            if 'proofing_version' in res:
                del res['proofing_version']
        return res
