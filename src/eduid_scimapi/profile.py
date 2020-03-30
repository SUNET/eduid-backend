from dataclasses import dataclass
from typing import Any, Dict, Mapping

from eduid_scimapi.scimbase import SCIMSchema

__author__ = 'ft'


@dataclass()
class Profile:
    external_id: str
    data: Dict[str, Any]

    def to_schema_dict(self, schema: str) -> Mapping[str, Any]:
        res = {}
        if schema == SCIMSchema.NUTID_V1.value:
            res = self.data
        if self.external_id:
            res['external_id'] = self.external_id
        return res
