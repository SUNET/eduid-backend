from __future__ import annotations

import logging
from abc import ABC
from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional, Union

from pydantic import Field

from eduid.userdb.element import ElementKey, VerifiedElement, VerifiedElementList

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class IdentityType(str, Enum):
    NIN = "nin"
    EIDAS = "eidas"
    SVIPE = "svipe"
    FREJA = "freja"


class IdentityProofingMethod(str, Enum):
    # difference in capitalization/underscore/hyphen is intentional as to follow existing proofing log entries
    SVIPE_ID = "svipe_id"
    LETTER = "letter"
    SE_LEG = "se-leg"
    SWEDEN_CONNECT = "swedenconnect"
    TELEADRESS = "TeleAdress"
    BANKID = "bankid"
    FREJA_EID = "freja_eid"


class IdentityElement(VerifiedElement, ABC):
    """
    Element that is used for an identity for a user

    Properties of IdentityElement:

        identity_type
    """

    identity_type: IdentityType
    proofing_method: Optional[IdentityProofingMethod] = None

    @property
    def key(self) -> ElementKey:
        """
        :return: Type of identity
        """
        return ElementKey(self.identity_type)

    @property
    def unique_key_name(self) -> str:
        """
        The identity types key name for the value that should be unique for a user
        """
        raise NotImplementedError("Sub-class must implement unique_key_name")

    @property
    def unique_value(self) -> str:
        """
        The identity types value that should be unique for a user
        """
        raise NotImplementedError("Sub-class must implement unique_value")

    def to_frontend_format(self) -> dict[str, Any]:
        return super().to_dict()

    def get_missing_proofing_method(self) -> Optional[IdentityProofingMethod]:
        """
        Returns the proofing method that is missing for this identity
        """
        match self.verified_by:
            case "bankid":
                return IdentityProofingMethod.BANKID
            case "eidas" | "eduid-eidas":
                return IdentityProofingMethod.SWEDEN_CONNECT
            case "eduid-idproofing-letter":
                return IdentityProofingMethod.LETTER
            case "lookup_mobile_proofing":
                return IdentityProofingMethod.TELEADRESS
            case "oidc_proofing":
                return IdentityProofingMethod.SE_LEG
            case "svipe_id":
                return IdentityProofingMethod.SVIPE_ID
            case "freja_eid":
                return IdentityProofingMethod.FREJA_EID
            case _:
                logger.warning(f"Unknown verified_by value: {self.verified_by}")
                return None


class NinIdentity(IdentityElement):
    """
    Element that is used as a NIN identity for a user

    Properties of NinIdentity:

        number
    """

    identity_type: Literal[IdentityType.NIN] = IdentityType.NIN
    number: str
    date_of_birth: Optional[datetime] = None

    @property
    def unique_key_name(self) -> str:
        return "number"

    @property
    def unique_value(self) -> str:
        return self.number

    def to_old_nin(self) -> dict[str, Union[str, bool]]:
        # TODO: remove nins after frontend stops using it
        return {"number": self.number, "verified": self.is_verified, "primary": True}


class ForeignIdentityElement(IdentityElement, ABC):
    country_code: str = Field(max_length=2)  # ISO 3166-1 alpha-2
    date_of_birth: datetime


class PridPersistence(str, Enum):
    A = "A"  # Persistence over time is expected to be comparable or better than a Swedish nin
    B = "B"  # Persistence over time is expected to be relatively stable, but lower than a Swedish nin
    C = "C"  # No expectations regarding persistence over time


class EIDASLoa(str, Enum):
    NF_LOW = "eidas-nf-low"
    NF_SUBSTANTIAL = "eidas-nf-sub"
    NF_HIGH = "eidas-nf-high"


class EIDASIdentity(ForeignIdentityElement):
    """
    Element that is used as an EIDAS identity for a user

    Properties of EIDASIdentity:

        prid
        prid_persistence
        loa
        country_code
    """

    identity_type: Literal[IdentityType.EIDAS] = IdentityType.EIDAS
    prid: str
    prid_persistence: PridPersistence
    loa: EIDASLoa

    @property
    def unique_key_name(self) -> str:
        return "prid"

    @property
    def unique_value(self) -> str:
        return self.prid


class SvipeIdentity(ForeignIdentityElement):
    """
    Element that is used as a Svipe identity for a user

    Properties of SvipeIdentity:

        svipe_id
        administrative_number
        country_code
    """

    identity_type: Literal[IdentityType.SVIPE] = IdentityType.SVIPE
    #  A globally unique identifier issued by Svipe to the user. Under normal conditions, a given person will retain
    #  the same Svipe ID even after renewing the underlying identity document.
    svipe_id: str
    administrative_number: Optional[str] = None

    @property
    def unique_key_name(self) -> str:
        return "svipe_id"

    @property
    def unique_value(self) -> str:
        return self.svipe_id


class FrejaRegistrationLevel(Enum):
    EXTENDED = "extended"
    PLUS = "plus"


class FrejaIdentity(ForeignIdentityElement):
    """
    Element that is used as a Freja identity for a user

    Properties of FrejaIdentity:

        user_id
        administrative_number
        registration_level
        country_code
    """

    identity_type: Literal[IdentityType.SVIPE] = IdentityType.SVIPE
    # claim: https://frejaeid.com/oidc/scopes/relyingPartyUserId
    # A unique, user-specific value that allows the Relying Party to identify the same user across multiple sessions
    user_id: str
    administrative_number: Optional[str] = None
    registration_level: FrejaRegistrationLevel

    @property
    def unique_key_name(self) -> str:
        return "user_id"

    @property
    def unique_value(self) -> str:
        return self.user_id


class IdentityList(VerifiedElementList[IdentityElement]):
    """
    Hold a list of IdentityElement instances.
    """

    @classmethod
    def from_list_of_dicts(cls: type[IdentityList], items: list[dict[str, Any]]) -> IdentityList:
        elements: list[IdentityElement] = []
        for item in items:
            _type = item["identity_type"]
            if _type == IdentityType.NIN.value:
                elements.append(NinIdentity.from_dict(item))
            elif _type == IdentityType.EIDAS.value:
                elements.append(EIDASIdentity.from_dict(item))
            elif _type == IdentityType.SVIPE.value:
                elements.append(SvipeIdentity.from_dict(item))
            elif _type == IdentityType.FREJA.value:
                elements.append(FrejaIdentity.from_dict(item))
            else:
                raise ValueError(f"identity_type {_type} not valid")
        return cls(elements=elements)

    def replace(self, element: IdentityElement) -> None:
        self.remove(key=element.key)
        self.add(element=element)
        return None

    @property
    def is_verified(self) -> bool:
        # TODO: the isinstance check should not be needed I think, but how to explain that to mypy?
        #   error: "ListElement" has no attribute "is_verified"
        return any([element.is_verified for element in self.elements if isinstance(element, IdentityElement)])

    @property
    def nin(self) -> Optional[NinIdentity]:
        _nin = self.filter(NinIdentity)
        if _nin:
            return _nin[0]
        return None

    @property
    def eidas(self) -> Optional[EIDASIdentity]:
        _eidas = self.filter(EIDASIdentity)
        if _eidas:
            return _eidas[0]
        return None

    @property
    def svipe(self) -> Optional[SvipeIdentity]:
        _svipe = self.filter(SvipeIdentity)
        if _svipe:
            return _svipe[0]
        return None

    @property
    def freja(self) -> Optional[FrejaIdentity]:
        _freja = self.filter(FrejaIdentity)
        if _freja:
            return _freja[0]
        return None

    @property
    def date_of_birth(self) -> Optional[datetime]:
        if not self.is_verified:
            return None
        # NIN
        if self.nin and self.nin.is_verified:
            if self.nin.date_of_birth is not None:
                return self.nin.date_of_birth
            # Fall back to parsing NIN
            try:
                try:
                    return datetime.strptime(self.nin.number[:8], "%Y%m%d")
                except ValueError:
                    # the nin might be a coordination number
                    day = int(self.nin.number[6:8])
                    if day >= 61:  # coordination number day is 61-91
                        day = day - 60
                    return datetime.strptime(self.nin.number[:6] + str(day).zfill(2), "%Y%m%d")
            except ValueError:
                logger.exception("Unable to parse user nin to date of birth")
                logger.debug(f"User nins: {self.nin}")
        # EIDAS
        if self.eidas and self.eidas.is_verified:
            return self.eidas.date_of_birth
        # SVIPE
        if self.svipe and self.svipe.is_verified:
            return self.svipe.date_of_birth
        return None

    def to_frontend_format(self) -> dict[str, Any]:
        res: dict[str, Union[bool, dict[str, Any]]] = {
            item.identity_type.value: item.to_frontend_format() for item in self.to_list()
        }
        res["is_verified"] = self.is_verified
        return res
