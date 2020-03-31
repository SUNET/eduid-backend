from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Mapping, Type

from eduid_scimapi.scimbase import SCIMSchema

__author__ = 'ft'


@dataclass()
class Profile:
    attributes: Dict[str, Any] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls: Type[Profile], data: Mapping[str, Any]) -> Profile:
        _attributes = data.get('attributes', {})
        _data = data.get('data', {})
        return cls(attributes=_attributes, data=_data)

    def to_schema_dict(self, schema: str) -> Mapping[str, Any]:
        res = {}
        if schema == SCIMSchema.NUTID_V1.value:
            res = asdict(self)
        return res
