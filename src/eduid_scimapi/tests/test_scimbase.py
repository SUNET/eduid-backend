# -*- coding: utf-8 -*-
from datetime import datetime
from unittest import TestCase
from uuid import uuid4

from bson import ObjectId
from marshmallow_dataclass import class_schema

from eduid_scimapi.scimbase import BaseResponse, Meta, SCIMResourceType, SCIMSchema, SubResource

__author__ = 'lundberg'


class TestScimBase(TestCase):
    def test_meta(self) -> None:
        meta = Meta(
            location='http://example.org/group/some-id',
            resource_type=SCIMResourceType.group,
            created=datetime.utcnow(),
            last_modified=datetime.utcnow(),
            version=ObjectId(),
        )
        schema = class_schema(Meta)
        meta_dump = schema().dump(meta)
        loaded_meta = schema().load(meta_dump)
        self.assertEqual(meta, loaded_meta)

    def test_base_response(self) -> None:
        meta = Meta(
            location='http://example.org/group/some-id',
            resource_type=SCIMResourceType.group,
            created=datetime.utcnow(),
            last_modified=datetime.utcnow(),
            version=ObjectId(),
        )
        base = BaseResponse(id=uuid4(), schemas=[SCIMSchema.CORE_20_USER, SCIMSchema.CORE_20_GROUP], meta=meta)
        schema = class_schema(BaseResponse)
        base_dump = schema().dump(base)
        loaded_base = schema().load(base_dump)
        self.assertEqual(base, loaded_base)

    def test_hashable_subresources(self):
        a = {
            '$ref': 'http://localhost:8000/Users/78130160-b63d-4303-99cd-73767e2a999f',
            'display': 'Test User 1 (updated)',
            'value': '78130160-b63d-4303-99cd-73767e2a999f',
        }
        b = {
            '$ref': 'http://localhost:8000/Groups/f194099c-23a9-4046-8cd6-79e472476fd2',
            'display': 'Test Group 2 (also updated)',
            'value': 'f194099c-23a9-4046-8cd6-79e472476fd2',
        }
        res_a = SubResource.from_mapping(a)
        res_b = SubResource.from_mapping(b)
        self.assertNotEqual(res_a, res_b)

        res_set = {res_a, res_b}
        self.assertIsInstance(res_set, set)
