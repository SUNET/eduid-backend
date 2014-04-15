from eduid_am.testing import MongoTestCase, MOCKED_USER_STANDARD as M
from eduid_am.exceptions import MultipleUsersReturned, UserDoesNotExist
from eduid_am.userdb import UserDB, User
from bson import ObjectId
import copy


class TestUserDB(MongoTestCase):
    def setUp(self):
        super(TestUserDB, self).setUp()
        mongo_settings = {
            'mongo_replicaset': None,
            'mongo_uri_am': self.am_settings['MONGO_URI'] + 'am',
        }
        self.udb = UserDB(mongo_settings)
        self._filter = {'mail': M['mail']}

    def test_get_user_by_nin(self):
        user = self.udb.get_user_by_nin(M['norEduPersonNIN'])
        self.assertEqual(user.get_eppn(), M['eduPersonPrincipalName'])
        self.assertRaises(UserDoesNotExist, self.udb.get_user_by_nin, 'foobar')

    def test_get_user_by_attr(self):
        user = self.udb.get_user_by_attr('mail', M['mail'])
        self.assertEqual(user.get_eppn(), M['eduPersonPrincipalName'])
        self.assertRaises(UserDoesNotExist, self.udb.get_user_by_attr, 'mail', 'doesnotexist')
        user = self.udb.get_user(M['mail'])
        self.assertEqual(user.get_eppn(), M['eduPersonPrincipalName'])

    def test_get_user_by_oid_as_string(self):
        user = self.udb.get_user_by_oid(str(M['_id']))
        self.assertEqual(user.get_eppn(), M['eduPersonPrincipalName'])

    def test_get_user_by_filter(self):
        user = self.udb.get_user_by_filter(self._filter)
        self.assertTrue(isinstance(user, User))
        doesnotexistfilter = {'mail': 'doesnotexist'}
        self.assertRaises(UserDoesNotExist, self.udb.get_user_by_filter, doesnotexistfilter)

    def test_exists(self):
        self.assertTrue(self.udb.exists_by_field('mail', M['mail']))
        self.assertTrue(self.udb.exists_by_filter(self._filter))

    def test_get_identity_proofing(self):
        user = self.udb.get_user_by_filter(self._filter)
        self.assertEqual(self.udb.get_identity_proofing(user), 'http://www.swamid.se/policy/assurance/al2')

    def test_get_user_by_username(self):
        user = self.udb.get_user_by_username(M['eduPersonPrincipalName'])
        self.assertEqual(user.get_eppn(), M['eduPersonPrincipalName'])
        self.assertRaises(UserDoesNotExist, self.udb.get_user_by_username, 'doesnotexist')

    def test_get_user_by_email(self):
        user = self.udb.get_user_by_email(M['mail'])
        self.assertEqual(user.get_mail(), M['mail'])

    def test_duplicate_users(self):
        user = copy.deepcopy(M)
        user['_id'] = ObjectId()
        self.amdb.attributes.insert(user)
        self.assertRaises(MultipleUsersReturned, self.udb.get_user_by_nin, M['norEduPersonNIN'][0])
        self.assertRaises(MultipleUsersReturned, self.udb.get_user_by_email, M['mail'])
        self.assertRaises(MultipleUsersReturned, self.udb.get_user_by_username, M['eduPersonPrincipalName'])
        self.assertRaises(MultipleUsersReturned, self.udb.get_user_by_attr, 'mail', M['mail'])
        self.assertRaises(MultipleUsersReturned, self.udb.get_user_by_filter, self._filter)
