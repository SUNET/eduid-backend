from copy import deepcopy
from datetime import datetime

import bson

from eduid_userdb.exceptions import UserDoesNotExist, UserHasUnknownData
from eduid_userdb.fixtures.users import mocked_user_standard
from eduid_userdb.signup import SignupUser

from eduid_am.ams import eduid_signup
from eduid_am.testing import AMTestCase
from eduid_am.tests.test_proofing_fetchers import USER_DATA

M = mocked_user_standard.to_dict()


class AttributeFetcherTests(AMTestCase):
    def setUp(self):
        am_settings = {'want_mongo_uri': True, 'new_user_date': '2001-01-01'}
        super(AttributeFetcherTests, self).setUp(am_settings=am_settings)

        self.fetcher = eduid_signup(self.am_settings)

        for userdoc in self.amdb._get_all_docs():
            signup_user = SignupUser(data=userdoc)
            self.fetcher.private_db.save(signup_user, check_sync=False)

    def test_invalid_user(self):
        with self.assertRaises(UserDoesNotExist):
            self.fetcher.fetch_attrs(bson.ObjectId('000000000000000000000000'))

    def test_existing_user_from_db(self):
        self.maxDiff = None
        expected = {
            '$set': {
                'eduPersonPrincipalName': 'hubba-bubba',
                'mailAliases': [
                    {
                        'created_by': 'signup',
                        'email': 'johnsmith@example.com',
                        'primary': True,
                        'verified': True,
                        'verified_by': 'signup',
                    },
                    {'email': 'johnsmith2@example.com', 'primary': False, 'verified': True},
                    {'email': 'johnsmith3@example.com', 'primary': False, 'verified': False},
                ],
                'passwords': [
                    {
                        'created_by': 'signup',
                        'credential_id': '112345678901234567890123',
                        'is_generated': False,
                        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
                    }
                ],
            }
        }
        res = self.fetcher.fetch_attrs(bson.ObjectId(M['_id']))
        # remove the datetimes from the response,
        # that carry their own tzinfo object from bson
        del res['$set']['mailAliases'][0]['created_ts']
        del res['$set']['mailAliases'][0]['verified_ts']
        del res['$set']['passwords'][0]['created_ts']

        assert res == expected

    def test_existing_user(self):
        user_data = deepcopy(USER_DATA)
        user_data['mail'] = 'johnsmith@example.com'
        user_data['mailAliases'] = [{'verified': True, 'email': 'johnsmith@example.com'}]
        del user_data['passwords']
        user = SignupUser(data=user_data)
        self.fetcher.private_db.save(user)
        with self.assertRaises(ValueError):
            self.fetcher.fetch_attrs(bson.ObjectId(user.user_id))

    def test_user_without_aliases(self):
        user_data = deepcopy(USER_DATA)
        user_data['mail'] = 'johnsmith@example.com'
        del user_data['passwords']
        user = SignupUser(data=user_data)
        self.fetcher.private_db.save(user)
        with self.assertRaises(ValueError):
            self.fetcher.fetch_attrs(bson.ObjectId(user.user_id))

    def test_user_finished_and_removed(self):
        user_data = deepcopy(USER_DATA)
        user_data['mail'] = 'john@example.com'
        user_data['mailAliases'] = [{'email': 'john@example.com', 'verified': True,}]
        user_data['passwords'] = [{'id': '123', 'salt': '456',}]
        user = SignupUser(data=user_data)
        self.fetcher.private_db.save(user)
        attrs = self.fetcher.fetch_attrs(user.user_id)
        self.assertEqual(
            attrs,
            {
                '$set': {
                    'eduPersonPrincipalName': 'test-test',
                    'mailAliases': [{'verified': True, 'primary': True, 'email': 'john@example.com'}],
                    'passwords': [{'credential_id': u'123', 'is_generated': False, 'salt': u'456',}],
                }
            },
        )

    def test_malicious_attributes(self):
        user_data = deepcopy(USER_DATA)
        user_data['foo'] = 'bar'
        user_data['mail'] = 'john@example.com'
        user_data['mailAliases'] = [{'email': 'john@example.com', 'verified': True,}]
        user_data['passwords'] = [{'id': '123', 'salt': '456',}]
        with self.assertRaises(UserHasUnknownData):
            SignupUser(data=user_data)
