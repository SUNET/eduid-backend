import unittest
from dataclasses import asdict
from datetime import datetime

from bson import ObjectId

from eduid_scimapi.scimbase import SCIMSchema
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
            SCIMSchema.NUTID_V1.value: {'student': {'attributes': {'displayName': 'Test'}, 'data': {}}},
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
            SCIMSchema.NUTID_V1.value: {'student': {'attributes': {}, 'data': {}}},
            'meta': {
                'created': '2020-03-30T10:12:08.528000',
                'lastModified': '2020-03-30T10:12:08.531000',
                'location': location,
                'resourceType': 'User',
                'version': 'W/"5e81c5f849ac2cd87580e502"',
            },
        }
        self.assertEqual(scim, expected)


if __name__ == '__main__':
    unittest.main()
