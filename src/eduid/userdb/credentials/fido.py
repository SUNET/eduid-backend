from __future__ import annotations

from hashlib import sha256
from typing import Any
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
    attest_cert: str | None = None

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

    authenticator_id: UUID | str | None = None
    credential_data: str
    authenticator: AuthenticatorAttachment
    webauthn_proofing_version: str | None = None
    attestation_format: AttestationFormat | None = None
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
