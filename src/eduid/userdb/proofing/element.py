from __future__ import annotations

from datetime import datetime
from typing import Any, TypeVar

from pydantic import field_validator

from eduid.common.rpc.msg_relay import FullPostalAddress
from eduid.userdb.element import Element, VerifiedElement

__author__ = "lundberg"


TProofingElementSubclass = TypeVar("TProofingElementSubclass", bound="ProofingElement")


class ProofingElement(VerifiedElement):
    """
    Element for holding the state of a proofing flow. It should contain meta data needed for logging
    a proofing according to the Kantara specification.

    Properties of ProofingElement:

        created_by
        created_ts
        is_verified
        verified_by
        verified_ts
        verification_code
    """

    verification_code: str | None = None

    @classmethod
    def _from_dict_transform(cls: type[TProofingElementSubclass], data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        # VerifiedElement._from_dict_transform eliminates the verification_code key, and here we keep it.
        code = data.pop("verification_code", None)

        data = super()._from_dict_transform(data)

        if code is not None:
            data["verification_code"] = code

        return data


class NinProofingElement(ProofingElement):
    """
    Element for holding the state of a nin proofing flow.

    Properties of NinProofingElement:

        number
        date_of_birth
        created_by
        created_ts
        is_verified
        verified_by
        verified_ts
        verification_code
    """

    number: str
    date_of_birth: datetime | None = None


class EmailProofingElement(ProofingElement):
    """
    Element for holding the state of an email proofing flow.

    Properties of EmailProofingElement:

        email
        created_by
        created_ts
        is_verified
        verified_by
        verified_ts
        verification_code
    """

    email: str

    @field_validator("email", mode="before")
    @classmethod
    def validate_email(cls, v: Any):
        if not isinstance(v, str):
            raise ValueError("must be a string")
        return v.lower()


class PhoneProofingElement(ProofingElement):
    """
    Element for holding the state of a phone number proofing flow.

    Properties of PhoneProofingElement:

        number
        created_by
        created_ts
        is_verified
        verified_by
        verified_ts
        verification_code
    """

    number: str


class SentLetterElement(Element):
    """
    Properties of SentLetterElement:

    address
    is_sent
    sent_ts
    transaction_id
    created_by
    created_ts
    """

    is_sent: bool = False
    sent_ts: datetime | None = None
    transaction_id: str | None = None
    address: FullPostalAddress | None = None
