from __future__ import annotations

from typing import Any

from eduid.userdb.credentials.base import Credential
from eduid.userdb.credentials.external import external_credential_from_dict
from eduid.userdb.credentials.fido import U2F, Webauthn
from eduid.userdb.credentials.password import Password
from eduid.userdb.element import ElementList
from eduid.userdb.exceptions import UserHasUnknownData


class CredentialList(ElementList[Credential]):
    """
    Hold a list of authentication credential instances.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there no duplicates in the list.
    """

    @classmethod
    def from_list_of_dicts(cls: type[CredentialList], items: list[dict[str, Any]]) -> CredentialList:
        elements = []
        for this in items:
            if not isinstance(this, dict):
                raise UserHasUnknownData(f"Unknown credential data (type {type(this)}): {this!r}")

            credential: Credential | None = None

            if "salt" in this:
                credential = Password.from_dict(this)
            elif "keyhandle" in this:
                if "public_key" in this:
                    credential = U2F.from_dict(this)
                else:
                    credential = Webauthn.from_dict(this)
            elif "framework" in this:
                credential = external_credential_from_dict(this)

            if credential:
                elements.append(credential)

        return cls(elements=elements)
