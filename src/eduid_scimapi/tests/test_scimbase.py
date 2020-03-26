# -*- coding: utf-8 -*-
from datetime import datetime
from unittest import TestCase
from uuid import uuid4

from bson import ObjectId
from marshmallow_dataclass import class_schema

from eduid_scimapi.scimbase import BaseResponse, Meta, SCIMResourceType, SCIMSchema

__author__ = 'lundberg'


class TestScimBase(TestCase):
    def setUp(self) -> None:
        self.meta = Meta(
            location='http://example.org/group/some-id',
            resource_type=SCIMResourceType.group,
            last_modified=datetime.utcnow(),
            version=ObjectId(),
        )
        self.base = BaseResponse(
            id=uuid4(), schemas=[SCIMSchema.CORE_20_USER, SCIMSchema.CORE_20_GROUP], meta=self.meta
        )

    def test_meta(self) -> None:
        schema = class_schema(Meta)
        meta_dump = schema().dump(self.meta)
        loaded_meta = schema().load(meta_dump)
        self.assertEqual(self.meta, loaded_meta)

    def test_base_response(self) -> None:
        schema = class_schema(BaseResponse)
        base_dump = schema().dump(self.base)
        loaded_base = schema().load(base_dump)
        self.assertEqual(self.base, loaded_base)
