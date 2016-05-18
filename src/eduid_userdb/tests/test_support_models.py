from eduid_userdb.testing import MOCKED_USER_STANDARD
from eduid_userdb.support import models

from unittest import TestCase


class TestSupportUsers(TestCase):

    def test_support_user(self):
        user = models.SupportUser(MOCKED_USER_STANDARD)
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)
        for password in user['passwords']:
            self.assertNotIn('salt', password)

    def test_support_dashboard_user(self):
        user = models.SupportDashboardUser(MOCKED_USER_STANDARD)
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)
        for password in user['passwords']:
            self.assertNotIn('salt', password)

    def test_support_signup_user(self):
        user = models.SupportDashboardUser(MOCKED_USER_STANDARD)
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)
        for password in user['passwords']:
            self.assertNotIn('salt', password)

