# -*- coding: utf-8 -*-

__author__ = 'lundberg'

import uuid
from uuid import uuid4

from bson import ObjectId
from marshmallow_dataclass import class_schema

from eduid_groupdb import Group as DBGroup
from eduid_groupdb import User as DBUser

from eduid_scimapi.group import GroupMember, GroupResponse
from eduid_scimapi.scimbase import SCIMSchema, make_etag
from eduid_scimapi.testing import ScimApiTestCase
from eduid_scimapi.tests.test_scimbase import TestScimBase
from eduid_scimapi.user import ScimApiUser


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
    def add_group(self, scope: str, identifier: str, display_name: str) -> DBGroup:
        group = DBGroup(scope=scope, identifier=identifier, display_name=display_name)
        return self.context.groupdb.save(group)

    def add_member(self, group: DBGroup, identifier: str, display_name: str) -> DBGroup:
        self.add_user(identifier=identifier, external_id='not-used')
        member = DBUser(identifier=identifier, display_name=display_name)
        group.members.append(member)
        return self.context.groupdb.save(group)

    def test_get_group(self):
        db_group = self.add_group(self.data_owner, str(uuid4()), 'Test Group 1')
        response = self.client.simulate_get(path=f'/Groups/{db_group.identifier}', headers=self.headers)
        self.assertEqual([SCIMSchema.CORE_20_GROUP.value], response.json.get('schemas'))
        self.assertEqual(db_group.identifier, response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Groups/{db_group.identifier}', response.headers.get('location'))
        self.assertEqual('Test Group 1', response.json.get('displayName'))
        self.assertEqual([], response.json.get('members'))

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

    def test_update_group(self):
        db_group = self.add_group(self.data_owner, str(uuid4()), 'Test Group 1')
        user = self.add_user(identifier=str(uuid4()), external_id='not-used')
        members = [
            {
                'value': str(user.scim_id),
                '$ref': f'http://localhost:8000/Users/{user.scim_id}',
                'display': 'Test User 1',
            }
        ]
        request = {
            'schemas': [SCIMSchema.CORE_20_GROUP.value],
            'id': db_group.identifier,
            'displayName': 'Another display name',
            'members': members,
        }
        self.headers['IF-MATCH'] = make_etag(db_group.version)
        response = self.client.simulate_put(
            path=f'/Groups/{db_group.identifier}', body=self.as_json(request), headers=self.headers
        )

        self.assertEqual([SCIMSchema.CORE_20_GROUP.value], response.json.get('schemas'))
        self.assertIsNotNone(response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Groups/{response.json.get("id")}', response.headers.get('location'))
        self.assertEqual('Another display name', response.json.get('displayName'))
        self.assertEqual(1, len(response.json.get('members')))
        self.assertEqual(members[0], response.json.get('members')[0])

        meta = response.json.get('meta')
        self.assertIsNotNone(meta)
        self.assertIsNotNone(meta.get('created'))
        self.assertIsNotNone(meta.get('lastModified'))
        self.assertIsNotNone(meta.get('version'))
        self.assertEqual(f'http://localhost:8000/Groups/{response.json.get("id")}', meta.get('location'))
        self.assertEqual(f'Group', meta.get('resourceType'))
