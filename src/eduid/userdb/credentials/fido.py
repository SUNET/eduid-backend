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

from hashlib import sha256
from typing import Any, Dict, Optional, Type, Union
from uuid import UUID

from fido2.webauthn import AuthenticatorAttachment

from eduid.userdb.credentials import Credential

__author__ = "ft"

from fido_mds.models.webauthn import AttestationFormat

from eduid.userdb.element import ElementKey


class FidoCredential(Credential):
    """
    Token authentication credential
    """

    keyhandle: str
    app_id: str
    description: str = ""


class U2F(FidoCredential):
    """
    U2F token authentication credential
    """

    version: str
    public_key: str
    attest_cert: Optional[str] = None

    @property
    def key(self) -> ElementKey:
        """
        Return the element that is used as key.
        """
        _digest = sha256(self.keyhandle.encode("utf-8") + self.public_key.encode("utf-8")).hexdigest()
        return ElementKey("sha256:" + _digest)


class Webauthn(FidoCredential):
    """
    Webauthn token authentication credential
    """

    authenticator_id: Optional[Union[UUID, str]] = None
    credential_data: str
    authenticator: AuthenticatorAttachment
    webauthn_proofing_version: Optional[str] = None
    attestation_format: Optional[AttestationFormat] = None
    mfa_approved: bool = False

    @property
    def key(self) -> ElementKey:
        """
        Return the element that is used as key.
        """
        _digest = sha256(self.keyhandle.encode("utf-8") + self.credential_data.encode("utf-8")).hexdigest()
        return ElementKey("sha256:" + _digest)

    @classmethod
    def _from_dict_transform(cls: type[Webauthn], data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data from eduid database format into pythonic format.
        """
        data = super()._from_dict_transform(data)

        # Add authenticator if not present.
        if "authenticator" not in data:
            data["authenticator"] = "cross-platform"

        # remove previously set attestation object data
        if "attest_obj" in data:
            del data["attest_obj"]

        return data
