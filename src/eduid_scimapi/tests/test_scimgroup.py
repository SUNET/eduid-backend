# -*- coding: utf-8 -*-

__author__ = 'lundberg'

import logging
from datetime import datetime
from uuid import UUID, uuid4

from bson import ObjectId
from marshmallow_dataclass import class_schema

from eduid_groupdb import Group as GraphGroup
from eduid_groupdb import User as GraphUser

from eduid_scimapi.group import GroupMember, GroupResponse
from eduid_scimapi.groupdb import ScimApiGroup
from eduid_scimapi.scimbase import Meta, SCIMResourceType, SCIMSchema, make_etag
from eduid_scimapi.testing import ScimApiTestCase
from eduid_scimapi.tests.test_scimbase import TestScimBase

logger = logging.getLogger(__name__)


class TestSCIMGroup(TestScimBase):
    def setUp(self) -> None:
        self.meta = Meta(
            location='http://example.org/Groups/some-id',
            resource_type=SCIMResourceType.group,
            created=datetime.utcnow(),
            last_modified=datetime.utcnow(),
            version=ObjectId(),
        )

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
    def setUp(self) -> None:
        super().setUp()
        self.groupdb = self.context.get_groupdb('eduid.se')

    def tearDown(self):
        super().tearDown()
        self.groupdb._drop_whole_collection()

    def add_group(self, scim_id: UUID, display_name: str) -> ScimApiGroup:
        group = ScimApiGroup(scim_id=scim_id, display_name=display_name)
        assert self.groupdb  # mypy doesn't know setUp will be called
        self.groupdb.save(group)
        group.graph = GraphGroup(identifier=str(group.scim_id), display_name=display_name)
        logger.info(f'TEST saved group {group}')
        self.groupdb.graphdb.save(group.graph)
        return group

    def add_member(self, group: ScimApiGroup, identifier: str, display_name: str) -> ScimApiGroup:
        self.add_user(identifier=identifier, external_id='not-used')
        member = GraphUser(identifier=identifier, display_name=display_name)
        group.graph.members.append(member)
        assert self.groupdb  # mypy doesn't know setUp will be called
        self.groupdb.save(group)
        return group

    def test_get_groups(self):
        for i in range(9):
            self.add_group(uuid4(), f'Test Group {i}')
        response = self.client.simulate_get(path=f'/Groups', headers=self.headers)
        self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], response.json.get('schemas'))
        resources = response.json.get('Resources')
        self.assertEqual(self.groupdb.graphdb.db.count_nodes(), len(resources))

    def test_get_group(self):
        db_group = self.add_group(uuid4(), 'Test Group 1')
        response = self.client.simulate_get(path=f'/Groups/{db_group.scim_id}', headers=self.headers)
        self.assertEqual([SCIMSchema.CORE_20_GROUP.value], response.json.get('schemas'))
        self.assertEqual(str(db_group.scim_id), response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Groups/{db_group.scim_id}', response.headers.get('location'))
        self.assertEqual('Test Group 1', response.json.get('displayName'))
        self.assertEqual([], response.json.get('members'))

        meta = response.json.get('meta')
        self.assertIsNotNone(meta)
        self.assertIsNotNone(meta.get('created'))
        self.assertIsNotNone(meta.get('lastModified'))
        self.assertIsNotNone(meta.get('version'))
        self.assertEqual(f'http://localhost:8000/Groups/{response.json.get("id")}', meta.get('location'))
        self.assertEqual(f'Group', meta.get('resourceType'))

    def test_create_group(self):
        req = {'schemas': [SCIMSchema.CORE_20_GROUP.value], 'displayName': 'Test Group 1', 'members': []}
        response = self.client.simulate_post(path='/Groups/', body=self.as_json(req), headers=self.headers)

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
        db_group = self.add_group(uuid4(), 'Test Group 1')
        user = self.add_user(identifier=str(uuid4()), external_id='not-used')
        members = [
            {
                'value': str(user.scim_id),
                '$ref': f'http://localhost:8000/Users/{user.scim_id}',
                'display': 'Test User 1',
            }
        ]
        req = {
            'schemas': [SCIMSchema.CORE_20_GROUP.value],
            'id': str(db_group.scim_id),
            'displayName': 'Another display name',
            'members': members,
        }
        self.headers['IF-MATCH'] = make_etag(db_group.version)
        response = self.client.simulate_put(
            path=f'/Groups/{db_group.scim_id}', body=self.as_json(req), headers=self.headers
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
        self.assertEqual(f'http://localhost:8000/Groups/{db_group.scim_id}', meta.get('location'))
        self.assertEqual(f'Group', meta.get('resourceType'))

    def test_search_group_display_name(self):
        db_group = self.add_group(uuid4(), 'Test Group 1')
        self.add_group(uuid4(), 'Test Group 2')
        req = {
            'schemas': [SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST.value],
            'filter': 'displayName eq "Test Group 1"',
            'startIndex': 1,
            'count': 10,
        }
        response = self.client.simulate_post(path='/Groups/.search', body=self.as_json(req), headers=self.headers)
        self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], response.json.get('schemas'))
        resources = response.json.get('Resources')
        self.assertEqual(1, len(resources))
        self.assertEqual(str(db_group.scim_id), resources[0].get('id'))
        self.assertEqual(db_group.display_name, resources[0].get('displayName'))

    def test_search_group_start_index(self):
        for i in range(9):
            self.add_group(uuid4(), f'Test Group')
        req = {
            'schemas': [SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST.value],
            'filter': 'displayName eq "Test Group"',
            'startIndex': 5,
            'count': 10,
        }
        response = self.client.simulate_post(path='/Groups/.search', body=self.as_json(req), headers=self.headers)
        self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], response.json.get('schemas'))
        resources = response.json.get('Resources')
        self.assertEqual(5, len(resources))
        # TODO: Implement correct totalResults
        # self.assertEqual(9, response.json.get('totalResults'))

    def test_search_group_count(self):
        for i in range(9):
            self.add_group(uuid4(), f'Test Group')
        req = {
            'schemas': [SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST.value],
            'filter': 'displayName eq "Test Group"',
            'startIndex': 1,
            'count': 5,
        }
        response = self.client.simulate_post(path='/Groups/.search', body=self.as_json(req), headers=self.headers)
        self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], response.json.get('schemas'))
        resources = response.json.get('Resources')
        self.assertEqual(5, len(resources))
        # TODO: Implement correct totalResults
        # self.assertEqual(9, response.json.get('totalResults'))
