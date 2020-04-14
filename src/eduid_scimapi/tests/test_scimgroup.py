# -*- coding: utf-8 -*-

__author__ = 'lundberg'

from uuid import uuid4

from marshmallow_dataclass import class_schema

from eduid_scimapi.group import GroupMember, GroupResponse
from eduid_scimapi.scimbase import SCIMSchema
from eduid_scimapi.testing import ScimApiTestCase
from eduid_scimapi.tests.test_scimbase import TestScimBase


class TestSCIMGroup(TestScimBase):
    def test_group(self) -> None:
        schema = class_schema(GroupResponse)
        group = GroupResponse(id=uuid4(), schemas=[SCIMSchema.CORE_20_GROUP], meta=self.meta, display_name='Test Group')
        member_1_id = uuid4()
        member_2_id = uuid4()
        group.members.extend(
            [
                GroupMember(value=member_1_id, display='Member 1', ref=f'https://some_domain/path/Users/{member_1_id}'),
                GroupMember(
                    value=member_2_id, display='Member 2', ref=f'https://some_domain/path/Groups/{member_2_id}'
                ),
            ]
        )
        group_dump = schema().dump(group)
        loaded_group = schema().load(group_dump)
        self.assertEqual(group, loaded_group)


class TestGroupResource(ScimApiTestCase):
    def test_create_group(self):
        request = {'schemas': [SCIMSchema.CORE_20_GROUP.value], 'displayName': 'Test Group 1', 'members': []}
        response = self.client.simulate_post(path='/Groups/', body=self.as_json(request), headers=self.headers)

        self.assertEqual([SCIMSchema.CORE_20_GROUP.value], response.json.get('schemas'))
        self.assertIsNotNone(response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Groups/{response.json.get("id")}', response.headers.get('location'))
        self.assertEqual('Test Group 1', response.json.get('displayName'))
        self.assertEqual([], response.json.get('members'))

        meta = response.json.get('meta')
        self.assertIsNotNone(meta)
        self.assertIsNotNone(meta.get('created'))
        self.assertIsNotNone(meta.get('lastModified'))
        self.assertIsNotNone(meta.get('version'))
        self.assertEqual(f'http://localhost:8000/Groups/{response.json.get("id")}', meta.get('location'))
        self.assertEqual(f'Group', meta.get('resourceType'))
