from abc import ABC
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, TypeVar

__author__ = "lundberg"

TPayload = TypeVar("TPayload", bound="Payload")


@dataclass
class Payload(ABC):
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls: type[TPayload], data: Mapping[str, Any]) -> TPayload:
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
    message: str
    created_ts: datetime = field(default_factory=datetime.utcnow)
    version: int = 1

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TestPayload":
        data = dict(data)  # Do not change caller data
        return cls(**data)
