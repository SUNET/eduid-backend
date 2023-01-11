from datetime import datetime
from unittest import TestCase
from uuid import uuid4

from eduid.common.models.scim_base import BaseResponse, Meta, SCIMResourceType, SCIMSchema, SubResource, WeakVersion
from eduid.common.testing_base import normalised_data

__author__ = "lundberg"


class TestScimBase(TestCase):
    def test_meta(self) -> None:
        meta = Meta(
            location="http://example.org/group/some-id",
            resource_type=SCIMResourceType.GROUP,
            created=datetime.utcnow(),
            last_modified=datetime.utcnow(),
            version=WeakVersion(),
        )
        meta_dump = meta.json()
        loaded_meta = Meta.parse_raw(meta_dump)
        assert normalised_data(meta.dict()) == normalised_data(loaded_meta.dict())

    def test_base_response(self) -> None:
        meta = Meta(
            location="http://example.org/group/some-id",
            resource_type=SCIMResourceType.GROUP,
            created=datetime.utcnow(),
            last_modified=datetime.utcnow(),
            version=WeakVersion(),
        )
        base = BaseResponse(id=uuid4(), schemas=[SCIMSchema.CORE_20_USER, SCIMSchema.CORE_20_GROUP], meta=meta)
        base_dump = base.json()
        loaded_base = BaseResponse.parse_raw(base_dump)
        assert normalised_data(base.dict()) == normalised_data(loaded_base.dict())

    def test_hashable_subresources(self):
        a = {
            "$ref": "http://localhost:8000/Users/78130160-b63d-4303-99cd-73767e2a999f",
            "display": "Test User 1 (updated)",
            "value": "78130160-b63d-4303-99cd-73767e2a999f",
        }
        b = {
            "$ref": "http://localhost:8000/Groups/f194099c-23a9-4046-8cd6-79e472476fd2",
            "display": "Test Group 2 (also updated)",
            "value": "f194099c-23a9-4046-8cd6-79e472476fd2",
        }
        res_a = SubResource.from_mapping(a)
        res_b = SubResource.from_mapping(b)
        self.assertNotEqual(res_a, res_b)

        res_set = {res_a, res_b}
        self.assertIsInstance(res_set, set)
