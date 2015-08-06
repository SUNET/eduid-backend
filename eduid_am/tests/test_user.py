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

    def test_verify_mail_and_set_as_primary(self):
        user = self.udb.get_user(M['mail'])

        # Save the original information so that
        # we can restore it after this test.
        old_mail_aliases = user.get_mail_aliases()
        old_mail = user.get_mail()

        # Remove the existing aliases and add one unverified
        user.set_mail_aliases([])
        user.set_mail_aliases(
            [{
            'email': 'testmail@example.com',
            'verified': False,
            }]
        )

        # Verify the only existing mail alias and since it
        # is the only existing mail address, set it as primary.
        user.add_verified_email('testmail@example.com')

        self.assertEqual(user.get_mail_aliases(), [{'verified': True, 'email': 'testmail@example.com'}])
        self.assertEqual(user.get_mail(), 'testmail@example.com')

        # Restore the old mail settings for other tests
        user.set_mail_aliases(old_mail_aliases)
        user.set_mail(old_mail)