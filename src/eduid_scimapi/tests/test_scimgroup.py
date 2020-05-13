# -*- coding: utf-8 -*-

__author__ = 'lundberg'

import logging
from datetime import datetime
from typing import Any, List, Mapping, Optional, Set
from uuid import UUID, uuid4

from bson import ObjectId
from marshmallow_dataclass import class_schema

from eduid_groupdb import Group as GraphGroup
from eduid_groupdb import User as GraphUser

from eduid_scimapi.group import GroupMember, GroupResponse
from eduid_scimapi.groupdb import GroupExtensions, ScimApiGroup
from eduid_scimapi.scimbase import Meta, SCIMResourceType, SCIMSchema, SubResource, make_etag
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

    def add_group(self, scim_id: UUID, display_name: str, extensions: Optional[GroupExtensions] = None) -> ScimApiGroup:
        if extensions is None:
            extensions = GroupExtensions()
        group = ScimApiGroup(scim_id=scim_id, display_name=display_name, extensions=extensions)
        assert self.groupdb  # mypy doesn't know setUp will be called
        self.groupdb.save(group)
        group.graph = GraphGroup(identifier=str(group.scim_id), display_name=display_name)
        # logger.info(f'TEST saved group {group}')
        self.groupdb.graphdb.save(group.graph)
        return group

    def add_member(self, group: ScimApiGroup, identifier: str, display_name: str) -> ScimApiGroup:
        self.add_user(identifier=identifier, external_id='not-used')
        member = GraphUser(identifier=identifier, display_name=display_name)
        group.graph.members.append(member)
        assert self.groupdb  # mypy doesn't know setUp will be called
        self.groupdb.save(group)
        return group

    def _perform_search(self, filter: str, start: int = 1, count: int = 10, return_json: bool = False):
        logger.info(f'Searching for group(s) using filter {repr(filter)}')
        req = {
            'schemas': [SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST.value],
            'filter': filter,
            'startIndex': start,
            'count': count,
        }
        response = self.client.simulate_post(path='/Groups/.search', body=self.as_json(req), headers=self.headers)
        logger.info(f'Search response:\n{response.json}')
        if return_json:
            return response.json
        self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], response.json.get('schemas'))
        return response.json.get('Resources')


class TestGroupResource_GET(TestGroupResource):
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

    def test_get_group_not_found(self):
        response = self.client.simulate_get(path=f'/Groups/{uuid4()}', headers=self.headers)
        self._assertScimError(response.json, status=404, detail='Group not found')


class TestGroupResource_POST(TestGroupResource):
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

    def test_schema_violation(self):
        # request missing displayName
        req = {'schemas': [SCIMSchema.CORE_20_GROUP.value], 'members': []}
        response = self.client.simulate_post(path=f'/Groups/', body=self.as_json(req), headers=self.headers)
        self._assertScimError(response.json, detail="{'displayName': ['Missing data for required field.']}")


class TestGroupResource_PUT(TestGroupResource):
    def test_update_group(self):
        db_group = self.add_group(uuid4(), 'Test Group 1')
        subgroup = self.add_group(uuid4(), 'Test Group 2')
        user = self.add_user(identifier=str(uuid4()), external_id='not-used')
        members = [
            {
                'value': str(user.scim_id),
                '$ref': f'http://localhost:8000/Users/{user.scim_id}',
                'display': 'Test User 1',
            },
            {
                'value': str(subgroup.scim_id),
                '$ref': f'http://localhost:8000/Groups/{subgroup.scim_id}',
                'display': 'Test Group 2',
            },
        ]
        req = {
            'schemas': [SCIMSchema.CORE_20_GROUP.value],
            'id': str(db_group.scim_id),
            'displayName': db_group.display_name,
            'members': members,
        }
        self.headers['IF-MATCH'] = make_etag(db_group.version)
        response = self.client.simulate_put(
            path=f'/Groups/{db_group.scim_id}', body=self.as_json(req), headers=self.headers
        )

        self.assertEqual([SCIMSchema.CORE_20_GROUP.value], response.json.get('schemas'))
        self.assertIsNotNone(response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Groups/{response.json.get("id")}', response.headers.get('location'))
        self.assertEqual(db_group.display_name, response.json.get('displayName'))
        self.assertEqual(members, response.json.get('members'))

        meta = response.json.get('meta')
        self.assertIsNotNone(meta)
        self.assertIsNotNone(meta.get('created'))
        self.assertIsNotNone(meta.get('lastModified'))
        self.assertIsNotNone(meta.get('version'))
        self.assertEqual(f'http://localhost:8000/Groups/{db_group.scim_id}', meta.get('location'))
        self.assertEqual(f'Group', meta.get('resourceType'))

    def test_update_existing_group(self):
        db_group = self.add_group(uuid4(), 'Test Group 1')
        subgroup = self.add_group(uuid4(), 'Test Group 2')
        user = self.add_user(identifier=str(uuid4()), external_id='not-used')
        members = [
            {
                'value': str(user.scim_id),
                '$ref': f'http://localhost:8000/Users/{user.scim_id}',
                'display': 'Test User 1',
            },
            {
                'value': str(subgroup.scim_id),
                '$ref': f'http://localhost:8000/Groups/{subgroup.scim_id}',
                'display': 'Test Group 2',
            },
        ]
        updated_display_name = 'Another display name'
        req = {
            'schemas': [SCIMSchema.CORE_20_GROUP.value, SCIMSchema.NUTID_GROUP_V1.value],
            'id': str(db_group.scim_id),
            'displayName': updated_display_name,
            'members': members,
            SCIMSchema.NUTID_GROUP_V1.value: {'data': {'test': 'updated'}},
        }
        self.headers['IF-MATCH'] = make_etag(db_group.version)
        response = self.client.simulate_put(
            path=f'/Groups/{db_group.scim_id}', body=self.as_json(req), headers=self.headers
        )

        self.assertEqual(req['schemas'], response.json.get('schemas'))
        self.assertIsNotNone(response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Groups/{response.json.get("id")}', response.headers.get('location'))
        self.assertEqual(updated_display_name, response.json.get('displayName'))
        self.assertSetEqual(_members_to_set(members), _members_to_set(response.json.get('members')))
        self.assertEqual(req[SCIMSchema.NUTID_GROUP_V1.value], response.json.get(SCIMSchema.NUTID_GROUP_V1.value))

        members[0]['display'] += ' (updated)'
        members[1]['display'] += ' (also updated)'

        self.headers['IF-MATCH'] = response.headers['Etag']
        response = self.client.simulate_put(
            path=f'/Groups/{db_group.scim_id}', body=self.as_json(req), headers=self.headers
        )
        self.assertSetEqual(_members_to_set(members), _members_to_set(response.json.get('members')))

    def test_add_member_to_existing_group(self):
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
            'displayName': db_group.display_name,
            'members': members,
        }
        self.headers['IF-MATCH'] = make_etag(db_group.version)
        response = self.client.simulate_put(
            path=f'/Groups/{db_group.scim_id}', body=self.as_json(req), headers=self.headers
        )

        self.assertEqual(req['schemas'], response.json.get('schemas'))
        self.assertIsNotNone(response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Groups/{response.json.get("id")}', response.headers.get('location'))
        self.assertEqual(db_group.display_name, response.json.get('displayName'))
        self.assertSetEqual(_members_to_set(members), _members_to_set(response.json.get('members')))

        # Now, add another user and make a new request

        added_user = self.add_user(identifier=str(uuid4()), external_id='not-used-2')
        members += [
            {
                'value': str(added_user.scim_id),
                '$ref': f'http://localhost:8000/Users/{added_user.scim_id}',
                'display': 'Added User',
            }
        ]

        self.headers['IF-MATCH'] = response.headers['Etag']
        response = self.client.simulate_put(
            path=f'/Groups/{db_group.scim_id}', body=self.as_json(req), headers=self.headers
        )
        self.assertEqual(_members_to_set(members), _members_to_set(response.json.get('members')))

    def test_removing_group_member(self):
        db_group = self.add_group(uuid4(), 'Test Group 1')
        subgroup = self.add_group(uuid4(), 'Test Group 2')
        user = self.add_user(identifier=str(uuid4()), external_id='not-used')
        members = [
            {
                'value': str(user.scim_id),
                '$ref': f'http://localhost:8000/Users/{user.scim_id}',
                'display': 'Test User 1',
            },
            {
                'value': str(subgroup.scim_id),
                '$ref': f'http://localhost:8000/Groups/{subgroup.scim_id}',
                'display': 'Test Group 2',
            },
        ]
        req = {
            'schemas': [SCIMSchema.CORE_20_GROUP.value, SCIMSchema.NUTID_GROUP_V1.value],
            'id': str(db_group.scim_id),
            'displayName': db_group.display_name,
            'members': members,
            SCIMSchema.NUTID_GROUP_V1.value: {'data': {'test': 'updated'}},
        }
        self.headers['IF-MATCH'] = make_etag(db_group.version)
        response = self.client.simulate_put(
            path=f'/Groups/{db_group.scim_id}', body=self.as_json(req), headers=self.headers
        )

        self.assertEqual(req['schemas'], response.json.get('schemas'))
        self.assertIsNotNone(response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Groups/{response.json.get("id")}', response.headers.get('location'))
        self.assertEqual(db_group.display_name, response.json.get('displayName'))
        self.assertSetEqual(_members_to_set(members), _members_to_set(response.json.get('members')))
        self.assertEqual(req[SCIMSchema.NUTID_GROUP_V1.value], response.json.get(SCIMSchema.NUTID_GROUP_V1.value))

        # Remove the second member
        req['members'] = [members[0]]

        self.headers['IF-MATCH'] = response.headers['Etag']
        response = self.client.simulate_put(
            path=f'/Groups/{db_group.scim_id}', body=self.as_json(req), headers=self.headers
        )
        self.assertSetEqual(_members_to_set(members), _members_to_set(response.json.get('members')))

    def test_update_group_id_mismatch(self):
        db_group = self.add_group(uuid4(), 'Test Group 1')
        req = {
            'schemas': [SCIMSchema.CORE_20_GROUP.value],
            'id': str(uuid4()),
            'displayName': 'Another display name',
            'members': [],
        }
        response = self.client.simulate_put(
            path=f'/Groups/{db_group.scim_id}', body=self.as_json(req), headers=self.headers
        )
        self._assertScimError(response.json, detail='Id mismatch')

    def test_update_group_not_found(self):
        req = {
            'schemas': [SCIMSchema.CORE_20_GROUP.value],
            'id': str(uuid4()),
            'displayName': 'Another display name',
            'members': [],
        }
        response = self.client.simulate_put(path=f'/Groups/{req["id"]}', body=self.as_json(req), headers=self.headers)
        self._assertScimError(response.json, status=404, detail='Group not found')

    def test_version_mismatch(self):
        db_group = self.add_group(uuid4(), 'Test Group 1')
        req = {
            'schemas': [SCIMSchema.CORE_20_GROUP.value],
            'id': str(db_group.scim_id),
            'displayName': 'Another display name',
        }
        self.headers['IF-MATCH'] = make_etag(ObjectId())
        response = self.client.simulate_put(
            path=f'/Groups/{db_group.scim_id}', body=self.as_json(req), headers=self.headers
        )
        self._assertScimError(response.json, detail='Version mismatch')

    def test_update_group_member_does_not_exist(self):
        db_group = self.add_group(uuid4(), 'Test Group 1')
        _user_scim_id = str(uuid4())
        members = [
            {'value': _user_scim_id, '$ref': f'http://localhost:8000/Users/{_user_scim_id}', 'display': 'Test User 1',}
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
        self._assertScimError(response.json, detail=f'User {_user_scim_id} not found')

    def test_update_group_subgroup_does_not_exist(self):
        db_group = self.add_group(uuid4(), 'Test Group 1')
        _subgroup_scim_id = str(uuid4())
        members = [
            {
                'value': _subgroup_scim_id,
                '$ref': f'http://localhost:8000/Groups/{_subgroup_scim_id}',
                'display': 'Test Group 2',
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
        self._assertScimError(response.json, detail=f'Group {_subgroup_scim_id} not found')

    def test_schema_violation(self):
        # request missing displayName
        req = {
            'schemas': [SCIMSchema.CORE_20_GROUP.value],
            'id': str(uuid4()),
        }
        response = self.client.simulate_put(path=f'/Groups/{uuid4()}', body=self.as_json(req), headers=self.headers)
        self._assertScimError(response.json, detail="{'displayName': ['Missing data for required field.']}")


class TestGroupResource_DELETE(TestGroupResource):
    def test_delete_group(self):
        group = self.add_group(uuid4(), 'Test Group 1')

        # Verify we can find the group in the database
        db_group1 = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        self.assertIsNotNone(db_group1)

        req = {'schemas': [SCIMSchema.CORE_20_GROUP.value]}
        self.headers['IF-MATCH'] = make_etag(group.version)
        response = self.client.simulate_delete(
            path=f'/Groups/{group.scim_id}', body=self.as_json(req), headers=self.headers
        )
        self.assertEqual(204, response.status_code)

        # Verify the group is no longer in the database
        db_group2 = self.groupdb.get_group_by_scim_id(group.scim_id)
        self.assertIsNone(db_group2)

    def test_version_mismatch(self):
        group = self.add_group(uuid4(), 'Test Group 1')

        req = {'schemas': [SCIMSchema.CORE_20_GROUP.value]}
        self.headers['IF-MATCH'] = make_etag(ObjectId())
        response = self.client.simulate_delete(
            path=f'/Groups/{group.scim_id}', body=self.as_json(req), headers=self.headers
        )
        self._assertScimError(response.json, detail='Version mismatch')

    def test_group_not_found(self):
        response = self.client.simulate_delete(path=f'/Groups/{uuid4()}', headers=self.headers)
        self._assertScimError(response.json, status=404, detail='Group not found')


class TestGroupSearchResource(TestGroupResource):
    def test_search_group_display_name(self):
        db_group = self.add_group(uuid4(), 'Test Group 1')
        self.add_group(uuid4(), 'Test Group 2')
        resources = self._perform_search(filter='displayName eq "Test Group 1"')
        self.assertEqual(1, len(resources))
        self.assertEqual(str(db_group.scim_id), resources[0].get('id'))
        self.assertEqual(db_group.display_name, resources[0].get('displayName'))

    def test_search_group_display_name_not_found(self):
        resources = self._perform_search(filter='displayName eq "Test No Such Group"')
        self.assertEqual(0, len(resources))

    def test_search_group_display_name_bad_operator(self):
        json = self._perform_search(filter='displayName lt 1', return_json=True)
        self._assertScimError(json, scim_type='invalidFilter', detail='Unsupported operator')

    def test_search_group_display_name_not_string(self):
        json = self._perform_search(filter='displayName eq 1', return_json=True)
        self._assertScimError(json, scim_type='invalidFilter', detail='Invalid displayName')

    def test_search_group_unknown_attribute(self):
        json = self._perform_search(filter='no_such_attribute lt 1', return_json=True)
        self._assertScimError(json, scim_type='invalidFilter', detail='Can\'t filter on attribute no_such_attribute')

    def test_search_group_start_index(self):
        for i in range(9):
            self.add_group(uuid4(), f'Test Group')
        json = self._perform_search(filter='displayName eq "Test Group"', start=5, return_json=True)
        resources = json['Resources']
        self.assertEqual(5, len(resources))
        self.assertEqual(9, json.get('totalResults'))

    def test_search_group_count(self):
        for i in range(9):
            self.add_group(uuid4(), f'Test Group')

        groups = self.groupdb.get_groups()
        self.assertEqual(len(groups), 9)

        json = self._perform_search(filter='displayName eq "Test Group"', start=1, count=5, return_json=True)
        resources = json.get('Resources')
        self.assertEqual(5, len(resources))
        self.assertEqual(9, json.get('totalResults'))

    def test_search_group_extension_data_attribute_str(self):
        ext = GroupExtensions(data={'some_key': "20072009"})
        db_group = self.add_group(uuid4(), 'Test Group with extension', extensions=ext)

        resources = self._perform_search(filter='extensions.data.some_key eq "20072009"')
        self.assertEqual(1, len(resources))
        self.assertEqual(str(db_group.scim_id), resources[0].get('id'))
        self.assertEqual(db_group.display_name, resources[0].get('displayName'))

    def test_search_group_extension_data_bad_op(self):
        json = self._perform_search(filter='extensions.data.some_key XY "20072009"', return_json=True)
        self._assertScimError(json, detail='Unsupported operator')

    def test_search_group_extension_data_invalid_key(self):
        json = self._perform_search(filter='extensions.data.some.key eq "20072009"', return_json=True)
        self._assertScimError(json, detail='Unsupported extension search key')

    def test_search_group_extension_data_not_found(self):
        resources = self._perform_search(filter='extensions.data.some_key eq "20072009"')
        self.assertEqual(0, len(resources))

    def test_search_group_extension_data_attribute_int(self):
        ext1 = GroupExtensions(data={'some_key': 20072009})
        group = self.add_group(uuid4(), 'Test Group with extension', extensions=ext1)

        # Add extra group that should not be matched by search
        ext2 = GroupExtensions(data={'some_key': 123})
        self.add_group(uuid4(), 'Test Group with extension', extensions=ext2)

        resources = self._perform_search(filter='extensions.data.some_key eq 20072009')
        self.assertEqual(1, len(resources))
        self.assertEqual(str(group.scim_id), resources[0].get('id'))
        self.assertEqual(group.display_name, resources[0].get('displayName'))

    def test_search_group_last_modified(self):
        group1 = self.add_group(uuid4(), 'Test Group 1')
        group2 = self.add_group(uuid4(), 'Test Group 2')
        self.assertGreater(group2.last_modified, group1.last_modified)

        resources = self._perform_search(filter=f'meta.lastModified ge "{group1.last_modified.isoformat()}"')
        self.assertEqual(2, len(resources))

        resources = self._perform_search(filter=f'meta.lastModified gt "{group1.last_modified.isoformat()}"')
        self.assertEqual(1, len(resources))
        self.assertEqual(str(group2.scim_id), resources[0].get('id'))
        self.assertEqual(group2.display_name, resources[0].get('displayName'))

    def test_search_group_last_modified_invalid_datetime_1(self):
        json = self._perform_search(filter=f'meta.lastModified ge 1', return_json=True)
        self._assertScimError(json, detail='Invalid datetime')

    def test_search_group_last_modified_invalid_datetime_2(self):
        json = self._perform_search(filter=f'meta.lastModified ge "2020-05-12_15:36:00+00"', return_json=True)
        self._assertScimError(json, detail='Invalid datetime')

    def test_schema_violation(self):
        # request missing filter
        req = {
            'schemas': [SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST.value],
        }
        response = self.client.simulate_post(path='/Groups/.search', body=self.as_json(req), headers=self.headers)
        self._assertScimError(response.json, detail="{'filter': ['Missing data for required field.']}")


class TestGroupExtensionData(TestGroupResource):
    def test_nutid_extension(self):
        display_name = 'Test Group with Nutid extension'
        nutid_data = {'data': {'testing': 'certainly'}}
        req = {
            'schemas': [SCIMSchema.CORE_20_GROUP.value],
            'displayName': display_name,
            'members': [],
            SCIMSchema.NUTID_GROUP_V1.value: nutid_data,
        }
        post_resp = self.client.simulate_post(path='/Groups/', body=self.as_json(req), headers=self.headers)

        # Verify NUTID data is part of the PUT response
        self.assertEqual(
            [SCIMSchema.CORE_20_GROUP.value, SCIMSchema.NUTID_GROUP_V1.value], post_resp.json.get('schemas')
        )
        scim_id = post_resp.json.get('id')
        self.assertIsNotNone(scim_id)
        self.assertEqual(f'http://localhost:8000/Groups/{post_resp.json.get("id")}', post_resp.headers.get('location'))
        self.assertEqual(display_name, post_resp.json.get('displayName'))
        self.assertEqual([], post_resp.json.get('members'))
        self.assertEqual(nutid_data, post_resp.json.get(SCIMSchema.NUTID_GROUP_V1.value))

        # Now fetch the group and validate the data
        get_resp = self.client.simulate_get(path=f'/Groups/{scim_id}', headers=self.headers)
        self.assertEqual(post_resp.json, get_resp.json)

        # And now, update the NUTID extension data
        nutid_data2 = {'data': {'testing': 'yes', 'other_key': 2}}
        req = {
            'schemas': [SCIMSchema.CORE_20_GROUP.value, SCIMSchema.NUTID_GROUP_V1.value],
            'id': str(scim_id),
            'displayName': display_name,
            'members': [],
            SCIMSchema.NUTID_GROUP_V1.value: nutid_data2,
        }
        self.headers['IF-MATCH'] = get_resp.json['meta']['version']
        put_resp = self.client.simulate_put(path=f'/Groups/{scim_id}', body=self.as_json(req), headers=self.headers)

        # Now fetch the group again and validate the data
        get_resp2 = self.client.simulate_get(path=f'/Groups/{scim_id}', headers=self.headers)
        self.assertEqual(put_resp.json, get_resp2.json)

        self.assertEqual(
            [SCIMSchema.CORE_20_GROUP.value, SCIMSchema.NUTID_GROUP_V1.value], get_resp2.json.get('schemas')
        )
        self.assertIsNotNone(get_resp2.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Groups/{get_resp2.json.get("id")}', get_resp2.headers.get('location'))
        self.assertEqual(display_name, get_resp2.json.get('displayName'))
        self.assertEqual([], get_resp2.json.get('members'))
        self.assertEqual(nutid_data2, get_resp2.json.get(SCIMSchema.NUTID_GROUP_V1.value))

        prev_meta = post_resp.json.get('meta')
        self.assertIsNotNone(prev_meta)
        meta = get_resp2.json.get('meta')
        self.assertIsNotNone(meta)
        self.assertEqual(meta['created'], prev_meta['created'])
        self.assertNotEqual(meta['lastModified'], prev_meta['lastModified'])
        self.assertNotEqual(meta['version'], prev_meta['version'])
        self.assertEqual(f'http://localhost:8000/Groups/{scim_id}', meta.get('location'))
        self.assertEqual('Group', meta.get('resourceType'))


def _members_to_set(members: List[Mapping[str, Any]]) -> Set[GroupMember]:
    res: Set[GroupMember] = set()
    for this in members:
        res.add(GroupMember.from_mapping(this))
    return res
