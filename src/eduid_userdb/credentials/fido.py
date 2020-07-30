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

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, Optional

from eduid_userdb.credentials import Credential

__author__ = 'ft'


@dataclass
class _FidoCredentialRequired:
    """
    Required fields for FidoCredential, so that they go before the optional
    arguments of Element in the implicit constructor.
    """

    keyhandle: str
    app_id: str


@dataclass
class FidoCredential(Credential, _FidoCredentialRequired):
    """
    Token authentication credential
    """

    description: str = ''

    def _data_out_transforms(self, data: Dict[str, Any], old_userdb_format: bool = False) -> Dict[str, Any]:
        """
        Transform data kept in pythonic format into eduid format.
        """
        if 'created_by' in data:
            data['application'] = data.pop('created_by')

        data = super()._data_out_transforms(data, old_userdb_format)

        return data


@dataclass
class _U2FCredentialRequired:
    """
    Required fields for U2F, so that they go before the optional
    arguments in the implicit constructor.
    """

    version: str
    public_key: str


@dataclass
class U2F(FidoCredential, _U2FCredentialRequired):
    """
    U2F token authentication credential
    """

    attest_cert: Optional[str] = None

    @property
    def key(self) -> str:
        """
        Return the element that is used as key.
        """
        return 'sha256:' + sha256(self.keyhandle.encode('utf-8') + self.public_key.encode('utf-8')).hexdigest()


def u2f_from_dict(data: Dict[str, Any]) -> U2F:
    """
    Create an U2F instance from a dict.

    :param data: Credential parameters from database
    """
    return U2F.from_dict(data)


@dataclass
class Webauthn(FidoCredential):
    """
    Webauthn token authentication credential
    """

    attest_obj: str = ''
    credential_data: str = ''

    @property
    def key(self) -> str:
        """
        Return the element that is used as key.
        """
        return 'sha256:' + sha256(self.keyhandle.encode('utf-8') + self.credential_data.encode('utf-8')).hexdigest()


def webauthn_from_dict(data: Dict[str, Any]) -> Webauthn:
    """
    Create an Webauthn instance from a dict.

    :param data: Credential parameters from database
    """
    return Webauthn.from_dict(data)
