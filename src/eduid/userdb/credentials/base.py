from __future__ import annotations

from enum import Enum
from typing import Any

from eduid.userdb.element import TVerifiedElementSubclass, VerifiedElement

__author__ = "ft"


# well-known proofing methods
class CredentialProofingMethod(str, Enum):
    SWAMID_AL2_MFA_HI = "SWAMID_AL2_MFA_HI"  # deprecated and replaced by SWAMID_AL3_MFA
    SWAMID_AL3_MFA = "SWAMID_AL3_MFA"


class Credential(VerifiedElement):
    """
    Base class for credentials.

    Adds 'proofing_method' to VerifiedElement. Maybe that could benefit the
    main VerifiedElement, but after a short discussion we chose to add it
    only for credentials until we know we want it for other types of verified
    elements too.

    There is some use of these objects as keys in dicts in eduid-IdP,
    so we are making them hashable.
    """

    proofing_method: CredentialProofingMethod | None = None

    def __str__(self) -> str:
        if len(self.key) == 24:
            # probably an object id in string format, don't cut it
            shortkey = str(self.key)
        else:
            shortkey = str(self.key[:12]) + "..."
        if self.is_verified:
            return (
                f"<eduID {self.__class__.__name__}(key={repr(shortkey)}): verified=True, "
                f"proofing=({repr(self.proofing_method)} v={repr(self.proofing_version)})>"
            )
        else:
            return f"<eduID {self.__class__.__name__}(key={repr(shortkey)}): verified=False>"

    def _to_dict_transform(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Make sure we never store proofing info for un-verified credentials
        """
        data = super()._to_dict_transform(data)

        if data.get("verified") is False:
            del data["verified"]
            if "proofing_method" in data:
                del data["proofing_method"]
            if "proofing_version" in data:
                del data["proofing_version"]
        return data

    @classmethod
    def _from_dict_transform(cls: type[TVerifiedElementSubclass], data: dict[str, Any]) -> dict[str, Any]:
        data = super()._from_dict_transform(data)
        # replace proofing_method SWAMID_AL2_MFA_HI with SWAMID_AL3_MFA
        if data.get("proofing_method") == CredentialProofingMethod.SWAMID_AL2_MFA_HI.value:
            data["proofing_method"] = CredentialProofingMethod.SWAMID_AL3_MFA.value
        return data
