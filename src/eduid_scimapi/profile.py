from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Mapping

from eduid_scimapi.scimbase import SCIMSchema

__author__ = 'ft'


@dataclass()
class Profile:
    attributes: Dict[str, Any] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)

    def to_schema_dict(self, schema: str) -> Mapping[str, Any]:
        res = {}
        if schema == SCIMSchema.NUTID_V1.value:
            res = asdict(self)
        return res
