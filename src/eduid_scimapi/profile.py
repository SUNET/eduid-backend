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


def parse_nutid_profiles(data: Mapping[str, Any]) -> Dict[str, Profile]:
    """ Parse the 'profiles' section of the NUTID v1 schema. """
    profiles = data.get('profiles', {})
    res: Dict[str, Profile] = {key: Profile.from_dict(values) for key, values in profiles.items()}
    return res
