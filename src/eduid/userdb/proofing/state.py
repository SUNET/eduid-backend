from __future__ import annotations

import copy
import datetime
import logging
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any, Self

import bson

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.exceptions import UserDBValueError
from eduid.userdb.proofing.element import (
    EmailProofingElement,
    NinProofingElement,
    PhoneProofingElement,
    SentLetterElement,
)

__author__ = "lundberg"

logger = logging.getLogger(__name__)


@dataclass()
class ProofingState:
    # __post_init__ will mint a new ObjectId if `id' is None
    id: bson.ObjectId | None
    eppn: str
    # Timestamp of last modification in the database.
    # None if ProofingState has never been written to the database.
    modified_ts: datetime.datetime | None

    def __post_init__(self) -> None:
        if self.id is None:
            self.id = bson.ObjectId()

    @classmethod
    def _default_from_dict(cls: type[Self], data: Mapping[str, Any], fields: set[str]) -> Self:
        _data = copy.deepcopy(dict(data))  # to not modify callers data
        if "eduPersonPrincipalName" in _data:
            _data["eppn"] = _data.pop("eduPersonPrincipalName")
        if "_id" in _data:
            _data["id"] = _data.pop("_id")

        # Can not use default args as those will be placed before non default args
        # in inheriting classes
        if not _data.get("id"):
            _data["id"] = None
        if not _data.get("modified_ts"):
            _data["modified_ts"] = None

        fields.update({"id", "eppn", "modified_ts"})
        _leftovers = [x for x in _data if x not in fields]
        if _leftovers:
            raise UserDBValueError(f"{cls}.from_dict() unknown data: {_leftovers}")

        return cls(**_data)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Any:  # noqa: ANN401
        raise NotImplementedError(f"from_dict not implemented for class {cls.__name__}")

    def to_dict(self) -> TUserDbDocument:
        res = asdict(self)
        res["_id"] = res.pop("id")
        res["eduPersonPrincipalName"] = res.pop("eppn")
        if res["modified_ts"] is True:
            res["modified_ts"] = utc_now()
        return TUserDbDocument(res)

    def __str__(self) -> str:
        return f"<eduID {self.__class__.__name__!s}: eppn={self.eppn!s}>"

    @property
    def reference(self) -> str:
        """Audit reference to help cross reference audit log and events."""
        return str(self.id)

    def is_expired(self, timeout_seconds: int) -> bool:
        """
        Check whether the code is expired.

        :param timeout_seconds: the number of seconds a code is valid
        """
        if not isinstance(self.modified_ts, datetime.datetime):
            if self.modified_ts is True or self.modified_ts is None:
                return False
            raise UserDBValueError(f"Malformed modified_ts: {repr(self.modified_ts)}")
        delta = datetime.timedelta(seconds=timeout_seconds)
        expiry_date = self.modified_ts + delta
        now = datetime.datetime.now(tz=self.modified_ts.tzinfo)
        return expiry_date < now

    def is_throttled(self, min_wait_seconds: int) -> bool:
        if not isinstance(self.modified_ts, datetime.datetime):
            if self.modified_ts is True or self.modified_ts is None:
                return False
            raise UserDBValueError(f"Malformed modified_ts: {repr(self.modified_ts)}")
        time_since_last_resend = utc_now() - self.modified_ts
        throttle_seconds = datetime.timedelta(seconds=min_wait_seconds)
        if time_since_last_resend < throttle_seconds:
            logger.warning(f"Resend throttled for {throttle_seconds - time_since_last_resend}")
            return True
        return False


@dataclass()
class NinProofingState(ProofingState):
    nin: NinProofingElement

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> NinProofingState:
        _data = copy.deepcopy(dict(data))  # to not modify callers data
        _data["nin"] = NinProofingElement.from_dict(_data["nin"])
        return cls._default_from_dict(_data, {"nin"})

    def to_dict(self) -> TUserDbDocument:
        nin_data = self.nin.to_dict()
        res = super().to_dict()
        res["nin"] = nin_data
        return res


@dataclass()
class LetterProofingState(NinProofingState):
    proofing_letter: SentLetterElement

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> LetterProofingState:
        _data = copy.deepcopy(dict(data))  # to not modify callers data
        _data["nin"] = NinProofingElement.from_dict(_data["nin"])
        _data["proofing_letter"] = SentLetterElement.from_dict(_data["proofing_letter"])
        return cls._default_from_dict(_data, {"nin", "proofing_letter"})

    def to_dict(self) -> TUserDbDocument:
        letter_data = self.proofing_letter.to_dict()
        res = super().to_dict()
        res["proofing_letter"] = letter_data
        return res


@dataclass()
class OrcidProofingState(ProofingState):
    state: str
    nonce: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> OrcidProofingState:
        return cls._default_from_dict(data, {"state", "nonce"})


@dataclass()
class EmailProofingState(ProofingState):
    verification: EmailProofingElement

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EmailProofingState:
        _data = copy.deepcopy(dict(data))  # to not modify callers data
        _data["verification"] = EmailProofingElement.from_dict(_data["verification"])
        return cls._default_from_dict(_data, {"verification"})

    def to_dict(self) -> TUserDbDocument:
        email_data = self.verification.to_dict()
        res = super().to_dict()
        res["verification"] = email_data
        return res


@dataclass()
class PhoneProofingState(ProofingState):
    verification: PhoneProofingElement

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PhoneProofingState:
        _data = copy.deepcopy(dict(data))  # to not modify callers data
        _data["verification"] = PhoneProofingElement.from_dict(_data["verification"])
        return cls._default_from_dict(_data, {"verification"})

    def to_dict(self) -> TUserDbDocument:
        phone_data = self.verification.to_dict()
        res = super().to_dict()
        res["verification"] = phone_data
        return res
