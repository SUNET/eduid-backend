from abc import ABC
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Self

from eduid.common.misc.timeutil import utc_now

__author__ = "lundberg"


@dataclass
class Payload(ABC):
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls: type[Self], data: Mapping[str, Any]) -> Self:
        raise NotImplementedError()

    @classmethod
    def get_type(cls) -> str:
        return cls.__name__


@dataclass
class RawPayload(Payload):
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return self.data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RawPayload":
        data = dict(data)  # Do not change caller data
        return cls(data=data)


@dataclass
class TestPayload(Payload):
    __test__: ClassVar[bool] = False
    message: str
    created_ts: datetime = field(default_factory=utc_now)
    version: int = 1

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TestPayload":
        data = dict(data)  # Do not change caller data
        return cls(**data)
