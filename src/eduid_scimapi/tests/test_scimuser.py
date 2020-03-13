import unittest
from dataclasses import asdict
from datetime import datetime

from bson import ObjectId

from eduid_scimapi.profile import NUTID_V1
from eduid_scimapi.user import ScimApiUser


class MyTestCase(unittest.TestCase):

    def setUp(self) -> None:
        self.user_doc1 = {
            "_id": ObjectId("5e5542db34a4cf8015e62ac8"),
            "scim_id": "9784e1bf-231b-4eb8-b315-52eb46dd7c4b",
            "version": ObjectId("5e5e6829f86abf66d341d4a2"),
            "created": datetime.fromisoformat("2020-02-25T15:52:59.745"),
            "last_modified": datetime.fromisoformat("2020-02-25T15:52:59.745"),
            "profiles": {
                "eduid": {
                    "external_id": "hubba-bubba",
                    "data": {
                        "display_name": "Test"
                    }
                }
            }
        }

    def test_load_old_user(self):
        user = ScimApiUser.from_dict(self.user_doc1)
        self.assertEqual(user.profiles['eduid'].data['display_name'], 'Test')

        # test to-dict+from-dict consistency
        user2 = ScimApiUser.from_dict(user.to_dict())
        self.assertEqual(asdict(user), asdict(user2))

    def test_to_scimuser_doc(self):
        user = ScimApiUser.from_dict(self.user_doc1)
        location = 'http://localhost:12345/User'
        scim = user.to_scim_dict(location=location)
        expected = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User', NUTID_V1],
            'externalId': 'hubba-bubba@eduid.se',
            'id': '9784e1bf-231b-4eb8-b315-52eb46dd7c4b',

            NUTID_V1: {'eduid': {'display_name': 'Test'}},

            'meta': {'created': '2020-02-25T15:52:59.745000',
                     'lastModified': '2020-02-25T15:52:59.745000',
                     'location': location,
                     'resourceType': 'User',
                     'version': 'W/"5e5e6829f86abf66d341d4a2"',
                     },
        }
        self.assertEqual(scim, expected)


if __name__ == '__main__':
    unittest.main()
