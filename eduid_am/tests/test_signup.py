import bson
from datetime import date, timedelta

from eduid_userdb.signup import SignupUser
from eduid_userdb.exceptions import UserDoesNotExist
from eduid_userdb.testing import MongoTestCase, MOCKED_USER_STANDARD as M
from eduid_signup_amp import attribute_fetcher, _attribute_transform, plugin_init


class AttributeFetcherTests(MongoTestCase):

    def setUp(self):
        am_settings = {
            'WANT_MONGO_URI': True,
            'NEW_USER_DATE': '2001-01-01'
        }
        super(AttributeFetcherTests, self).setUp(init_am=True, am_settings=am_settings)

        self.plugin_context = plugin_init(self.am_settings)

        for userdoc in self.amdb._get_all_docs():
            signup_user = SignupUser(data = userdoc)
            self.plugin_context.signup_userdb.save(signup_user, check_sync=False)

    def test_invalid_user(self):
        with self.assertRaises(UserDoesNotExist):
            attribute_fetcher(self.plugin_context, bson.ObjectId('000000000000000000000000'))

    def test_existing_user_from_db(self):
        self.maxDiff = None
        expected = {
            'displayName': 'John Smith',
            'eduPersonPrincipalName': 'hubba-bubba',
            'givenName': 'John',
            'mailAliases': [
                {'email': 'johnsmith@example.com', 'primary': True, 'verified': True},
                {'email': 'johnsmith2@example.com', 'primary': False, 'verified': True},
                {'email': 'johnsmith3@example.com', 'primary': False, 'verified': False}
            ],
            'passwords': [{
                'credential_id': '112345678901234567890123',
                'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$'
            }],
            'surname': 'Smith',
            'tou': []
        }

        res = attribute_fetcher(self.plugin_context, bson.ObjectId(M['_id']))
        self.assertEqual(res, expected)

    def test_existing_user(self):
        user_doc = {
            'mail': 'johnsmith@example.com',
            'mailAliases': [{'verified': True, 'email': 'johnsmith@example.com'}],
        }
        res, signup_finished, = _attribute_transform(user_doc, 'unit testing')
        self.assertEqual(
            res,
            {
                'mail': 'johnsmith@example.com',
                'mailAliases': [{
                    'email': 'johnsmith@example.com',
                    'verified': True,
                }],
            }
        )
        self.assertFalse(signup_finished)

    def test_user_without_aliases(self):
        user_doc = {
            'mail': 'john@example.com',
        }
        res, signup_finished, = _attribute_transform(user_doc, 'unit testing')
        self.assertEqual(
            res,
            {
                'mail': 'john@example.com',
            }
        )
        self.assertFalse(signup_finished)

    def test_malicious_attributes(self):
        user_doc = {
            'givenName': 'Test',
            'malicious': 'hacker',
        }
        # Malicious attributes are not returned
        res, signup_finished, = _attribute_transform(user_doc, 'unit testing')
        self.assertEqual(
            res,
            {
                'givenName': 'Test',
            }
        )
        self.assertFalse(signup_finished)

    def test_user_finished_and_removed(self):
        user_doc = {
            'mail': 'john@example.com',
            'mailAliases': [{'verified': True, 'email': 'john@example.com'}],
            'verified': True,
            'passwords': [{
                'id': '123',
                'salt': '456',
            }]
        }
        res, signup_finished, = _attribute_transform(user_doc, 'unit testing')
        self.assertEqual(
            res,
            {
                'mail': 'john@example.com',
                'mailAliases': [{
                    'email': 'john@example.com',
                    'verified': True,
                }],
                'passwords': [{
                    'id': u'123',
                    'salt': u'456',
                }]
            }
        )
        self.assertTrue(signup_finished)


class AttributeFetcherTestsNewUsers(MongoTestCase):

    def setUp(self):
        am_settings = {
            'WANT_MONGO_URI': True,
            'NEW_USER_DATE': '2001-01-01'
        }
        super(AttributeFetcherTestsNewUsers, self).setUp(init_am=True, am_settings=am_settings)

        self.plugin_context = plugin_init(self.am_settings)

        for userdoc in self.amdb._get_all_docs():
            signup_user = SignupUser(data = userdoc)
            self.plugin_context.signup_userdb.save(signup_user, check_sync=False)

    def test_invalid_user(self):
        with self.assertRaises(UserDoesNotExist):
            attribute_fetcher(self.plugin_context, bson.ObjectId('000000000000000000000000'))

    def test_existing_user_from_db(self):
        self.maxDiff = None
        expected = {'passwords': [{'salt': u'$NDNv1H1$9c810d852430b62a9a7c6159d5d64c4'
                                   '1c3831846f81b6799b54e1e8922f11545$32$32$',
                                   'credential_id': u'112345678901234567890123'}],
                    'displayName': u'John Smith',
                    'mailAliases': [{'verified': True, 'primary': True, 'email': 'johnsmith@example.com'},
                                    {'verified': True, 'primary': False, 'email': 'johnsmith2@example.com'},
                                    {'verified': False, 'primary': False, 'email': 'johnsmith3@example.com'}],
                    'surname': u'Smith',
                    'eduPersonPrincipalName': u'hubba-bubba',
                    'givenName': u'John',
                    'tou': []
                    }

        res = attribute_fetcher(self.plugin_context, bson.ObjectId(M['_id']))
        self.assertEqual(res, expected)

    def test_existing_user(self):
        user_doc = {
            'mail': 'johnsmith@example.com',
            'mailAliases': [{'verified': True, 'email': 'johnsmith@example.com'}],
        }
        res, signup_finished, = _attribute_transform(user_doc, 'unit testing')
        self.assertEqual(
            res,
            {
                'mail': 'johnsmith@example.com',
                'mailAliases': [{
                    'email': 'johnsmith@example.com',
                    'verified': True,
                }],
            }
        )
        self.assertFalse(signup_finished)

    def test_user_without_aliases(self):
        user_doc = {
            'mail': 'john@example.com',
        }
        res, signup_finished, = _attribute_transform(user_doc, 'unit testing')
        self.assertEqual(
            res,
            {
                'mail': 'john@example.com',
            }
        )
        self.assertFalse(signup_finished)

    def test_malicious_attributes(self):
        user_doc = {
            'givenName': 'Test',
            'malicious': 'hacker',
        }
        # Malicious attributes are not returned
        res, signup_finished, = _attribute_transform(user_doc, 'unit testing')
        self.assertEqual(
            res,
            {
                'givenName': 'Test',
            }
        )
        self.assertFalse(signup_finished)

    def test_user_finished_and_removed(self):
        user_doc = {
            'mail': 'john@example.com',
            'mailAliases': [{'verified': True, 'email': 'john@example.com'}],
            'verified': True,
            'passwords': [{
                'id': '123',
                'salt': '456',
            }]
        }
        res, signup_finished, = _attribute_transform(user_doc, 'unit testing')
        self.assertEqual(
            res,
            {
                'mail': 'john@example.com',
                'mailAliases': [{
                    'email': 'john@example.com',
                    'verified': True,
                }],
                'passwords': [{
                    'id': u'123',
                    'salt': u'456',
                }]
            }
        )
        self.assertTrue(signup_finished)

