from unittest import TestCase
from uuid import uuid4

from bson import ObjectId

from eduid.common.misc.timeutil import utc_now
from eduid.common.models.scim_base import BaseResponse, Meta, SCIMResourceType, SCIMSchema, SubResource
from eduid.common.testing_base import normalised_data

__author__ = "lundberg"


class TestScimBase(TestCase):
    def test_meta(self) -> None:
        meta = Meta(
            location="http://example.org/group/some-id",
            resource_type=SCIMResourceType.GROUP,
            created=utc_now(),
            last_modified=utc_now(),
            version=ObjectId(),
        )
        meta_dump = meta.model_dump_json()
        loaded_meta = Meta.model_validate_json(meta_dump)
        assert normalised_data(meta.model_dump()) == normalised_data(loaded_meta.model_dump())

    def test_base_response(self) -> None:
        meta = Meta(
            location="http://example.org/group/some-id",
            resource_type=SCIMResourceType.GROUP,
            created=utc_now(),
            last_modified=utc_now(),
            version=ObjectId(),
        )
        base = BaseResponse(id=uuid4(), schemas=[SCIMSchema.CORE_20_USER, SCIMSchema.CORE_20_GROUP], meta=meta)
        base_dump = base.model_dump_json()
        loaded_base = BaseResponse.model_validate_json(base_dump)
        assert normalised_data(base.model_dump()) == normalised_data(loaded_base.model_dump())

    def test_hashable_subresources(self) -> None:
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
