import json
import logging
import unittest
from collections import Mapping
from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

import bson
from bson import ObjectId

from eduid_scimapi.db.userdb import Profile, ScimApiUser
from eduid_scimapi.schemas.scimbase import Meta, SCIMResourceType, SCIMSchema
from eduid_scimapi.schemas.user import NutidUserExtensionV1, UserResponse, UserResponseSchema
from eduid_scimapi.testing import ScimApiTestCase
from eduid_scimapi.utils import make_etag

logger = logging.getLogger(__name__)


class TestScimUser(unittest.TestCase):
    def setUp(self) -> None:
        self.maxDiff = None
        self.user_doc1 = {
            "_id": ObjectId("5e5542db34a4cf8015e62ac8"),
            "scim_id": "9784e1bf-231b-4eb8-b315-52eb46dd7c4b",
            "external_id": "hubba-bubba@eduid.se",
            "name": {
                "givenName": "Test",
                "familyName": "Testsson",
                "middleName": "Testaren",
                "formatted": "Test T. Testsson",
            },
            "emails": [
                {"value": "johnsmith@example.com", "type": "other", "primary": True},
                {"value": "johnsmith2@example.com", "type": "home", "primary": False},
            ],
            "phone_numbers": [
                {"value": "tel:+461234567", "type": "fax", "primary": True},
                {"value": "tel:+5-555-555-5555", "type": "home", "primary": False},
            ],
            "preferred_language": "se-SV",
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
            resource_type=SCIMResourceType.USER,
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
            emails=db_user.emails,
            phone_numbers=db_user.phone_numbers,
            name=db_user.name,
            nutid_user_v1=NutidUserExtensionV1(profiles=db_user.profiles),
        )

        scim = UserResponseSchema().dumps(user_response, sort_keys=True)
        # Validation does not occur on serialization
        UserResponseSchema().loads(scim)

        expected = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User', SCIMSchema.NUTID_USER_V1.value],
            'emails': [
                {'primary': True, 'type': 'other', 'value': 'johnsmith@example.com'},
                {'primary': False, 'type': 'home', 'value': 'johnsmith2@example.com'},
            ],
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
            'name': {
                'familyName': 'Testsson',
                'formatted': 'Test T. Testsson',
                'givenName': 'Test',
                'middleName': 'Testaren',
            },
            'phoneNumbers': [
                {'primary': True, 'type': 'fax', 'value': 'tel:+461234567'},
                {'primary': False, 'type': 'home', 'value': 'tel:+5-555-555-5555'},
            ],
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
            resource_type=SCIMResourceType.USER,
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
            nutid_user_v1=NutidUserExtensionV1(profiles=db_user.profiles),
        )

        scim = UserResponseSchema().dumps(user_response)
        UserResponseSchema().validate(scim)

        expected = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User', SCIMSchema.NUTID_USER_V1.value],
            'id': 'a7851d21-eab9-4caa-ba5d-49653d65c452',
            'emails': [],
            'groups': [],
            SCIMSchema.NUTID_USER_V1.value: {'profiles': {'student': {'attributes': {}, 'data': {}}}},
            'meta': {
                'created': '2020-03-30T10:12:08.528000',
                'lastModified': '2020-03-30T10:12:08.531000',
                'location': f'http://example.org/Users/{db_user.scim_id}',
                'resourceType': 'User',
                'version': 'W/"5e81c5f849ac2cd87580e502"',
            },
            'name': {},
            'phoneNumbers': [],
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

    def _assertUserUpdateSuccess(self, req: Mapping, response, user: ScimApiUser):
        """ Function to validate successful responses to SCIM calls that update a group according to a request. """
        if response.json.get('schemas') == [SCIMSchema.ERROR.value]:
            self.fail(f'Got SCIM error response ({response.status}):\n{response.json}')

        expected_schemas = req.get('schemas', [SCIMSchema.CORE_20_USER.value])
        if SCIMSchema.NUTID_USER_V1.value in response.json and SCIMSchema.NUTID_USER_V1.value not in expected_schemas:
            # The API can always add this extension to the response, even if it was not in the request
            expected_schemas += [SCIMSchema.NUTID_USER_V1.value]

        self._assertScimResponseProperties(response, resource=user, expected_schemas=expected_schemas)

        # Validate user update specifics
        self.assertEqual(user.external_id, response.json.get('externalId'))

        # If the request has NUTID profiles, ensure they are present in the response
        if SCIMSchema.NUTID_USER_V1.value in req:
            self.assertEqual(
                req[SCIMSchema.NUTID_USER_V1.value],
                response.json.get(SCIMSchema.NUTID_USER_V1.value),
                'Unexpected NUTID user data in response',
            )
        elif SCIMSchema.NUTID_USER_V1.value in response.json:
            self.fail(f'Unexpected {SCIMSchema.NUTID_USER_V1.value} in the response')

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

        _req = {
            SCIMSchema.NUTID_USER_V1.value: {'profiles': {'test': asdict(self.test_profile)}},
        }
        self._assertUserUpdateSuccess(_req, response, db_user)

    def test_create_user(self):
        req = {
            'schemas': [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
            'externalId': 'test-id-1',
            SCIMSchema.NUTID_USER_V1.value: {
                'profiles': {'test': {'attributes': {'displayName': 'Test User 1'}, 'data': {'test_key': 'test_value'}}}
            },
        }
        response = self.client.simulate_post(path='/Users/', body=self.as_json(req), headers=self.headers)

        # Load the created user from the database, ensuring it was in fact created
        db_user = self.userdb.get_user_by_external_id(req['externalId'])
        self.assertIsNotNone('Created user not found in the database')

        self._assertUserUpdateSuccess(req, response, db_user)

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

        self._assertUserUpdateSuccess(req, response, db_user)

    def test_search_user_external_id(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id='test-id-1', profiles={'test': self.test_profile})
        self.add_user(identifier=str(uuid4()), external_id='test-id-2', profiles={'test': self.test_profile})
        self._perform_search(filter=f'externalId eq "{db_user.external_id}"', expected_user=db_user)

    def test_search_user_last_modified(self):
        db_user1 = self.add_user(identifier=str(uuid4()), external_id='test-id-1', profiles={'test': self.test_profile})
        db_user2 = self.add_user(identifier=str(uuid4()), external_id='test-id-2', profiles={'test': self.test_profile})
        self.assertGreater(db_user2.last_modified, db_user1.last_modified)

        self._perform_search(
            filter=f'meta.lastModified ge "{db_user1.last_modified.isoformat()}"',
            expected_num_resources=2,
            expected_total_results=2,
        )

        self._perform_search(
            filter=f'meta.lastModified gt "{db_user1.last_modified.isoformat()}"', expected_user=db_user2
        )

    def test_search_user_start_index(self):
        for i in range(9):
            self.add_user(identifier=str(uuid4()), external_id=f'test-id-{i}', profiles={'test': self.test_profile})
        self.assertEqual(9, self.userdb.db_count())
        last_modified = datetime.utcnow() - timedelta(hours=1)
        self._perform_search(
            filter=f'meta.lastmodified gt "{last_modified.isoformat()}"',
            start=5,
            return_json=True,
            expected_num_resources=5,
            expected_total_results=9,
        )

    def test_search_user_count(self):
        for i in range(9):
            self.add_user(identifier=str(uuid4()), external_id=f'test-id-{i}', profiles={'test': self.test_profile})
        self.assertEqual(9, self.userdb.db_count())
        last_modified = datetime.utcnow() - timedelta(hours=1)
        self._perform_search(
            filter=f'meta.lastmodified gt "{last_modified.isoformat()}"',
            count=5,
            return_json=True,
            expected_num_resources=5,
            expected_total_results=9,
        )

    def test_search_user_start_index_and_count(self):
        for i in range(9):
            self.add_user(identifier=str(uuid4()), external_id=f'test-id-{i}', profiles={'test': self.test_profile})
        self.assertEqual(9, self.userdb.db_count())
        last_modified = datetime.utcnow() - timedelta(hours=1)
        self._perform_search(
            filter=f'meta.lastmodified gt "{last_modified.isoformat()}"',
            start=7,
            count=5,
            return_json=True,
            expected_num_resources=3,
            expected_total_results=9,
        )

    def _perform_search(
        self,
        filter: str,
        start: int = 1,
        count: int = 10,
        return_json: bool = False,
        expected_user: Optional[ScimApiUser] = None,
        expected_num_resources: Optional[int] = None,
        expected_total_results: Optional[int] = None,
    ):
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
        expected_schemas = [SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value]
        response_schemas = response.json.get('schemas')
        self.assertIsInstance(response_schemas, list, 'Response schemas not present, or not a list')
        self.assertEqual(
            sorted(set(expected_schemas)), sorted(set(response_schemas)), 'Unexpected schema(s) in search response'
        )

        resources = response.json.get('Resources')

        if expected_user is not None:
            expected_num_resources = 1
            expected_total_results = 1

        if expected_num_resources is not None:
            self.assertEqual(
                expected_num_resources,
                len(resources),
                f'Number of resources returned expected to be {expected_num_resources}',
            )
            if expected_total_results is None:
                expected_total_results = expected_num_resources
        if expected_total_results is not None:
            self.assertEqual(
                expected_total_results,
                response.json.get('totalResults'),
                f'Response totalResults expected to be {expected_total_results}',
            )

        if expected_user is not None:
            self.assertEqual(
                str(expected_user.scim_id),
                resources[0].get('id'),
                f'Search response user does not have the expected id: {str(expected_user.scim_id)}',
            )

        self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], response.json.get('schemas'))
        resources = response.json.get('Resources')
        return resources
