from dataclasses import dataclass
from typing import Any, Dict, Mapping

__author__ = 'ft'


# schemas
NUTID_V1 = 'https://scim.eduid.se/schema/nutid/v1'
DEBUG_ALL_V1 = 'https://scim.eduid.se/schema/debug-all-profiles/v1'


@dataclass()
class Profile():
    external_id: str
    data: Dict[str, Any]

    def to_schema_dict(self, schema: str) -> Mapping[str, Any]:
        res = {}
        if schema == NUTID_V1:
            res = self.data
        return res
