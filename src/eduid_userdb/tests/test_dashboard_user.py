from eduid_userdb.testing import MOCKED_USER_STANDARD
from eduid_userdb.dashboard import DashboardLegacyUser as User

from unittest import TestCase


class TestUser(TestCase):

    def test_verify_mail_and_set_as_primary(self):
        user = User(MOCKED_USER_STANDARD)

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