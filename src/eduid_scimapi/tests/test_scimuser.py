import unittest
from dataclasses import asdict
from datetime import datetime
from uuid import uuid4

import bson
from bson import ObjectId

from eduid_scimapi.profile import Profile
from eduid_scimapi.scimbase import SCIMSchema, make_etag
from eduid_scimapi.testing import ScimApiTestCase
from eduid_scimapi.user import ScimApiUser


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
        user = ScimApiUser.from_dict(self.user_doc1)
        location = 'http://localhost:12345/User'
        scim = user.to_scim_dict(location=location)
        expected = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User', SCIMSchema.NUTID_V1.value],
            'externalId': 'hubba-bubba@eduid.se',
            'id': '9784e1bf-231b-4eb8-b315-52eb46dd7c4b',
            SCIMSchema.NUTID_V1.value: {'profiles': {'student': {'attributes': {'displayName': 'Test'}, 'data': {}}}},
            'meta': {
                'created': '2020-02-25T15:52:59.745000',
                'lastModified': '2020-02-25T15:52:59.745000',
                'location': location,
                'resourceType': 'User',
                'version': 'W/"5e5e6829f86abf66d341d4a2"',
            },
        }
        self.assertEqual(scim, expected)

    def test_to_scimuser_not_eduid(self):
        user_doc2 = {
            '_id': ObjectId('5e81c5f849ac2cd87580e500'),
            'scim_id': 'a7851d21-eab9-4caa-ba5d-49653d65c452',
            'version': ObjectId('5e81c5f849ac2cd87580e502'),
            'created': datetime.fromisoformat('2020-03-30T10:12:08.528'),
            'last_modified': datetime.fromisoformat('2020-03-30T10:12:08.531'),
            'profiles': {'student': {'data': {}}},
        }
        user = ScimApiUser.from_dict(user_doc2)
        location = 'http://localhost:12345/User'
        scim = user.to_scim_dict(location=location)
        expected = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User', SCIMSchema.NUTID_V1.value],
            'id': 'a7851d21-eab9-4caa-ba5d-49653d65c452',
            SCIMSchema.NUTID_V1.value: {'profiles': {'student': {'attributes': {}, 'data': {}}}},
            'meta': {
                'created': '2020-03-30T10:12:08.528000',
                'lastModified': '2020-03-30T10:12:08.531000',
                'location': location,
                'resourceType': 'User',
                'version': 'W/"5e81c5f849ac2cd87580e502"',
            },
        }
        self.assertEqual(scim, expected)

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

    def test_get_user(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id='test-id-1', profiles={'test': self.test_profile})
        response = self.client.simulate_get(path=f'/Users/{db_user.scim_id}', headers=self.headers)
        self.assertEqual([SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_V1.value], response.json.get('schemas'))
        self.assertEqual(str(db_user.scim_id), response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Users/{db_user.scim_id}', response.headers.get('location'))
        self.assertEqual('test-id-1', response.json.get('externalId'))

        nutid = response.json.get(SCIMSchema.NUTID_V1.value)
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
            'schemas': [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_V1.value],
            'externalId': 'test-id-1',
            SCIMSchema.NUTID_V1.value: {
                'profiles': {'test': {'attributes': {'displayName': 'Test User 1'}, 'data': {'test_key': 'test_value'}}}
            },
        }
        response = self.client.simulate_post(path='/Users/', body=self.as_json(req), headers=self.headers)

        # TODO: SCIMSchema.DEBUG_V1 should be returned if not asked for
        self.assertEqual(
            [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_V1.value, SCIMSchema.DEBUG_V1.value],
            response.json.get('schemas'),
        )
        self.assertIsNotNone(response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Users/{response.json.get("id")}', response.headers.get('location'))
        self.assertEqual('test-id-1', response.json.get('externalId'))

        nutid = response.json.get(SCIMSchema.NUTID_V1.value)
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
            'schemas': [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_V1.value],
            'id': str(db_user.scim_id),
            'externalId': 'test-id-1',
            SCIMSchema.NUTID_V1.value: {
                'profiles': {'test': {'attributes': {'displayName': 'Test User 1'}, 'data': {'test_key': 'test_value'}}}
            },
        }
        self.headers['IF-MATCH'] = make_etag(db_user.version)
        response = self.client.simulate_put(
            path=f'/Users/{db_user.scim_id}', body=self.as_json(req), headers=self.headers
        )

        self.assertEqual([SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_V1.value], response.json.get('schemas'))
        self.assertIsNotNone(response.json.get('id'))
        self.assertEqual(f'http://localhost:8000/Users/{response.json.get("id")}', response.headers.get('location'))
        self.assertEqual('test-id-1', response.json.get('externalId'))

        nutid = response.json.get(SCIMSchema.NUTID_V1.value)
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

    def test_search_user_external_id(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id='test-id-1', profiles={'test': self.test_profile})
        self.add_user(identifier=str(uuid4()), external_id='test-id-2', profiles={'test': self.test_profile})
        req = {
            'schemas': [SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST.value],
            'filter': f'externalid eq "{db_user.external_id}"',
            'startIndex': 1,
            'count': 10,
        }
        response = self.client.simulate_post(path='/Users/.search', body=self.as_json(req), headers=self.headers)
        self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], response.json.get('schemas'))
        resources = response.json.get('Resources')
        self.assertEqual(1, len(resources))
        self.assertEqual(str(db_user.scim_id), resources[0].get('id'))
