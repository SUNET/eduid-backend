# -*- coding: utf-8 -*-

__author__ = 'lundberg'

from uuid import uuid4

from marshmallow_dataclass import class_schema

from eduid_scimapi.group import GroupMember, GroupResponse
from eduid_scimapi.scimbase import SCIMSchema
from eduid_scimapi.tests.test_scimbase import TestScimBase


class TestSCIMGroup(TestScimBase):
    def test_group(self) -> None:
        schema = class_schema(GroupResponse)
        group = GroupResponse(id=uuid4(), schemas=[SCIMSchema.CORE_20_GROUP], meta=self.meta, display_name='Test Group')
        group.members.extend(
            [GroupMember(id=uuid4(), display_name='Member 1'), GroupMember(id=uuid4(), display_name='Member 2')]
        )
        group_dump = schema().dump(group)
        loaded_group = schema().load(group_dump)
        self.assertEqual(group, loaded_group)
