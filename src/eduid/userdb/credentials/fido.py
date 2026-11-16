from __future__ import annotations

from datetime import datetime
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
    mfa_approved: bool = False


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
    # Facts about the credential that are only known from a registration or a key check. All optional: absent means
    # "not known", and nothing writes them yet, so that every app version can read them before the first write.
    is_discoverable: bool | None = None  # credProps.rk at registration, or proven by a usernameless key check
    backup_eligible: bool | None = None  # BE flag of the authenticator data (fixed for a credential)
    backup_state: bool | None = None  # BS flag of the authenticator data (can change, refreshed by a key check)
    key_checked_ts: datetime | None = None  # the last successful key check
    transports: list[str] | None = None  # getTransports() of the registration response

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
