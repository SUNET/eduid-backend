from eduid_am.testing import MongoTestCase, MOCKED_USER_STANDARD as M
from eduid_am.userdb import UserDB


class TestUser(MongoTestCase):
    def setUp(self):
        super(TestUser, self).setUp()
        mongo_settings = {
            'mongo_replicaset': None,
            'mongo_uri_am': self.am_settings['MONGO_URI'] + 'am',
        }
        self.udb = UserDB(mongo_settings)

    def test_user_object(self):
        user = self.udb.get_user(M['mail'])
        self.assertEqual(user.__repr__(), '<User: hubba-bubba>')
        self.assertEqual(user.get_mail(), M['mail'])
        self.assertEqual(user.get_eppn(), M['eduPersonPrincipalName'])
        self.assertEqual(user.get_display_name(), M['displayName'])
        user_dict = user.get_doc()
        self.assertEqual(user_dict['mail'], M['mail'])
