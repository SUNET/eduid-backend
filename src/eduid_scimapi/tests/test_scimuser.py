import json
import logging
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta
from uuid import uuid4

import bson
from bson import ObjectId
from marshmallow_dataclass import class_schema

from eduid_scimapi.scimbase import Meta, SCIMResourceType, SCIMSchema, make_etag
from eduid_scimapi.testing import ScimApiTestCase
from eduid_scimapi.user import NutidExtensionV1, UserResponse, UserResponseSchema
from eduid_scimapi.userdb import Profile, ScimApiUser

logger = logging.getLogger(__name__)


class TestScimUser(unittest.TestCase):
    def setUp(self) -> None:
        self.maxDiff = None
        self.user_doc1 = {
            "_id": ObjectId("5e5542db34a4cf8015e62ac8"),
            "scim_id": "9784e1bf-231b-4eb8-b315-52eb46dd7c4b",
            "external_id": "hubba-bubba@eduid.se",
            "version": ObjectId("5e5e6829f86abf66d341d4a2"),
            "created": datetime.fromisoformat("2020-02-25T15:52:59.745"),
            "last_modified": datetime.fromisoformat("2020-02-25T15:52:59.745"),
            "profiles": {"student": {"attributes": {"displayName": "Test"}}},
        }

    def test_load_old_user(self):
        user = ScimApiUser.from_dict(self.user_doc1)
        self.assertEqual(user.profiles['student'].attributes['displayName'], 'Test')

        # test to-dict+from-dict consistency
        user2 = ScimApiUser.from_dict(user.to_dict())
        self.assertEqual(asdict(user), asdict(user2))

    def test_to_scimuser_doc(self):
        db_user = ScimApiUser.from_dict(self.user_doc1)
        meta = Meta(
            location=f'http://example.org/Users/{db_user.scim_id}',
            resource_type=SCIMResourceType.user,
            created=db_user.created,
            last_modified=db_user.last_modified,
            version=db_user.version,
        )

        user_response = UserResponse(
            id=db_user.scim_id,
            meta=meta,
            schemas=[SCIMSchema.CORE_20_USER, SCIMSchema.NUTID_USER_V1],
            external_id=db_user.external_id,
            groups=[],
            nutid_v1=NutidExtensionV1(profiles=db_user.profiles),
        )
        schema = class_schema(UserResponse)
        scim = schema().dumps(user_response, sort_keys=True)

        expected = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User', SCIMSchema.NUTID_USER_V1.value],
            'externalId': 'hubba-bubba@eduid.se',
            'id': '9784e1bf-231b-4eb8-b315-52eb46dd7c4b',
            'groups': [],
            SCIMSchema.NUTID_USER_V1.value: {
                'profiles': {'student': {'attributes': {'displayName': 'Test'}, 'data': {}}}
            },
            'meta': {
                'created': '2020-02-25T15:52:59.745000',
                'lastModified': '2020-02-25T15:52:59.745000',
                'location': f'http://example.org/Users/{db_user.scim_id}',
                'resourceType': 'User',
                'version': 'W/"5e5e6829f86abf66d341d4a2"',
            },
        }
        self.assertDictEqual(expected, json.loads(scim))

    def test_to_scimuser_no_external_id(self):
        user_doc2 = {
            '_id': ObjectId('5e81c5f849ac2cd87580e500'),
            'scim_id': 'a7851d21-eab9-4caa-ba5d-49653d65c452',
            'version': ObjectId('5e81c5f849ac2cd87580e502'),
            'created': datetime.fromisoformat('2020-03-30T10:12:08.528'),
            'last_modified': datetime.fromisoformat('2020-03-30T10:12:08.531'),
            'profiles': {'student': {'data': {}}},
        }
        db_user = ScimApiUser.from_dict(user_doc2)

        meta = Meta(
            location=f'http://example.org/Users/{db_user.scim_id}',
            resource_type=SCIMResourceType.user,
            created=db_user.created,
            last_modified=db_user.last_modified,
            version=db_user.version,
        )

        user_response = UserResponse(
            id=db_user.scim_id,
            meta=meta,
            schemas=[SCIMSchema.CORE_20_USER, SCIMSchema.NUTID_USER_V1],
            external_id=db_user.external_id,
            groups=[],
            nutid_v1=NutidExtensionV1(profiles=db_user.profiles),
        )
        scim = UserResponseSchema().dumps(user_response)

        expected = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User', SCIMSchema.NUTID_USER_V1.value],
            'id': 'a7851d21-eab9-4caa-ba5d-49653d65c452',
            'groups': [],
            SCIMSchema.NUTID_USER_V1.value: {'profiles': {'student': {'attributes': {}, 'data': {}}}},
            'meta': {
                'created': '2020-03-30T10:12:08.528000',
                'lastModified': '2020-03-30T10:12:08.531000',
                'location': f'http://example.org/Users/{db_user.scim_id}',
                'resourceType': 'User',
                'version': 'W/"5e81c5f849ac2cd87580e502"',
            },
        }
        self.assertDictEqual(expected, json.loads(scim))

    def test_bson_serialization(self):
        user = ScimApiUser.from_dict(self.user_doc1)
        x = bson.encode(user.to_dict())
        self.assertTrue(x)


class TestUserResource(ScimApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.test_profile = Profile()
        self.test_profile.attributes['displayName'] = 'Test User 1'
        self.test_profile.data = {'test_key': 'test_value'}

    # TODO: Should we implement this?
    # def test_get_users(self):
    #    for i in range(9):
    #        self.add_user(identifier=str(uuid4()), external_id=f'test-id-{i}', profiles={'test': self.test_profile})
    #    response = self.client.simulate_get(path=f'/Users', headers=self.headers)
    #    self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], response.json.get('schemas'))
    #    resources = response.json.get('Resources')
    #    self.assertEqual(self.userdb.db_count(), len(resources))

    def test_get_user(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id='test-id-1', profiles={'test': self.test_profile})
        response = self.client.simulate_get(path=f'/Users/{db_user.scim_id}', headers=self.headers)
        self.assertEqual([SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value], response.json.get('schemas'))
        self.assertEqual(str(db_user.scim_id), response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Users/{db_user.scim_id}', response.headers.get('location'))
        self.assertEqual('test-id-1', response.json.get('externalId'))

        nutid = response.json.get(SCIMSchema.NUTID_USER_V1.value)
        self.assertIsNotNone(nutid.get('profiles'))
        test_profile = nutid.get('profiles').get('test')
        self.assertEqual(self.test_profile.attributes, test_profile.get('attributes'))
        self.assertEqual(self.test_profile.data, test_profile.get('data'))

        meta = response.json.get('meta')
        self.assertIsNotNone(meta)
        self.assertIsNotNone(meta.get('created'))
        self.assertIsNotNone(meta.get('lastModified'))
        self.assertIsNotNone(meta.get('version'))
        self.assertEqual(f'http://localhost:8000/Users/{response.json.get("id")}', meta.get('location'))
        self.assertEqual(f'User', meta.get('resourceType'))

    def test_create_user(self):
        req = {
            'schemas': [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
            'externalId': 'test-id-1',
            SCIMSchema.NUTID_USER_V1.value: {
                'profiles': {'test': {'attributes': {'displayName': 'Test User 1'}, 'data': {'test_key': 'test_value'}}}
            },
        }
        response = self.client.simulate_post(path='/Users/', body=self.as_json(req), headers=self.headers)

        self.assertEqual(
            [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value], response.json.get('schemas'),
        )
        self.assertIsNotNone(response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Users/{response.json.get("id")}', response.headers.get('location'))
        self.assertEqual('test-id-1', response.json.get('externalId'))

        nutid = response.json.get(SCIMSchema.NUTID_USER_V1.value)
        self.assertIsNotNone(nutid.get('profiles'))
        test_profile = nutid.get('profiles').get('test')
        self.assertEqual(self.test_profile.attributes, test_profile.get('attributes'))
        self.assertEqual(self.test_profile.data, test_profile.get('data'))

        meta = response.json.get('meta')
        self.assertIsNotNone(meta)
        self.assertIsNotNone(meta.get('created'))
        self.assertIsNotNone(meta.get('lastModified'))
        self.assertIsNotNone(meta.get('version'))
        self.assertEqual(f'http://localhost:8000/Users/{response.json.get("id")}', meta.get('location'))
        self.assertEqual(f'User', meta.get('resourceType'))

    def test_update_user(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id='test-id-1', profiles={'test': self.test_profile})
        req = {
            'schemas': [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
            'id': str(db_user.scim_id),
            'externalId': 'test-id-1',
            SCIMSchema.NUTID_USER_V1.value: {
                'profiles': {
                    'test': {'attributes': {'displayName': 'New display name'}, 'data': {'test_key': 'new value'}}
                }
            },
        }
        self.headers['IF-MATCH'] = make_etag(db_user.version)
        response = self.client.simulate_put(
            path=f'/Users/{db_user.scim_id}', body=self.as_json(req), headers=self.headers
        )

        self.assertEqual([SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value], response.json.get('schemas'))
        self.assertIsNotNone(response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Users/{response.json.get("id")}', response.headers.get('location'))
        self.assertEqual('test-id-1', response.json.get('externalId'))

        nutid = response.json.get(SCIMSchema.NUTID_USER_V1.value)
        self.assertIsNotNone(nutid.get('profiles'))
        excepted_profile = req[SCIMSchema.NUTID_USER_V1.value].get('profiles').get('test')
        test_profile = nutid.get('profiles').get('test')
        self.assertEqual(excepted_profile.get('attributes'), test_profile.get('attributes'))
        self.assertEqual(excepted_profile.get('data'), test_profile.get('data'))

        meta = response.json.get('meta')
        self.assertIsNotNone(meta)
        self.assertIsNotNone(meta.get('created'))
        self.assertIsNotNone(meta.get('lastModified'))
        self.assertIsNotNone(meta.get('version'))
        self.assertEqual(f'http://localhost:8000/Users/{response.json.get("id")}', meta.get('location'))
        self.assertEqual(f'User', meta.get('resourceType'))

    def test_search_user_external_id(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id='test-id-1', profiles={'test': self.test_profile})
        self.add_user(identifier=str(uuid4()), external_id='test-id-2', profiles={'test': self.test_profile})
        resources = self._perform_search(filter=f'externalId eq "{db_user.external_id}"')
        self.assertEqual(1, len(resources))
        self.assertEqual(str(db_user.scim_id), resources[0].get('id'))

    def test_search_user_last_modified(self):
        db_user1 = self.add_user(identifier=str(uuid4()), external_id='test-id-1', profiles={'test': self.test_profile})
        db_user2 = self.add_user(identifier=str(uuid4()), external_id='test-id-2', profiles={'test': self.test_profile})
        self.assertGreater(db_user2.last_modified, db_user1.last_modified)

        resources = self._perform_search(filter=f'meta.lastmodified ge "{db_user1.last_modified.isoformat()}"')
        self.assertEqual(2, len(resources))

        resources = self._perform_search(filter=f'meta.lastmodified gt "{db_user1.last_modified.isoformat()}"')
        self.assertEqual(1, len(resources))

    def test_search_user_start_index(self):
        for i in range(9):
            self.add_user(identifier=str(uuid4()), external_id=f'test-id-{i}', profiles={'test': self.test_profile})
        self.assertEqual(9, self.userdb.db_count())
        last_modified = datetime.utcnow() - timedelta(hours=1)
        json = self._perform_search(
            filter=f'meta.lastmodified gt "{last_modified.isoformat()}"', start=5, return_json=True
        )
        resources = json.get('Resources')
        self.assertEqual(5, len(resources))
        self.assertEqual(9, json.get('totalResults'))

    def test_search_user_count(self):
        for i in range(9):
            self.add_user(identifier=str(uuid4()), external_id=f'test-id-{i}', profiles={'test': self.test_profile})
        self.assertEqual(9, self.userdb.db_count())
        last_modified = datetime.utcnow() - timedelta(hours=1)
        json = self._perform_search(
            filter=f'meta.lastmodified gt "{last_modified.isoformat()}"', count=5, return_json=True
        )
        resources = json.get('Resources')
        self.assertEqual(5, len(resources))
        self.assertEqual(9, json.get('totalResults'))

    def test_search_user_start_index_and_count(self):
        for i in range(9):
            self.add_user(identifier=str(uuid4()), external_id=f'test-id-{i}', profiles={'test': self.test_profile})
        self.assertEqual(9, self.userdb.db_count())
        last_modified = datetime.utcnow() - timedelta(hours=1)
        json = self._perform_search(
            filter=f'meta.lastmodified gt "{last_modified.isoformat()}"', start=7, count=5, return_json=True
        )
        resources = json.get('Resources')
        self.assertEqual(3, len(resources))
        self.assertEqual(9, json.get('totalResults'))

    def _perform_search(self, filter: str, start: int = 1, count: int = 10, return_json: bool = False):
        logger.info(f'Searching for group(s) using filter {repr(filter)}')
        req = {
            'schemas': [SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST.value],
            'filter': filter,
            'startIndex': start,
            'count': count,
        }
        response = self.client.simulate_post(path='/Users/.search', body=self.as_json(req), headers=self.headers)
        logger.info(f'Search response:\n{response.json}')
        if return_json:
            return response.json
        self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], response.json.get('schemas'))
        resources = response.json.get('Resources')
        return resources
