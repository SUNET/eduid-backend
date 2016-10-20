from eduid_userdb.data_samples import NEW_USER_EXAMPLE, NEW_SIGNUP_USER_EXAMPLE, NEW_DASHBOARD_USER_EXAMPLE
from eduid_userdb.data_samples import OLD_USER_EXAMPLE, OLD_VERIFICATIONS_EXAMPLE
from eduid_userdb.support import models

from unittest import TestCase


class TestSupportUsers(TestCase):

    def test_old_support_user(self):
        user = models.SupportUser(OLD_USER_EXAMPLE)
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)
        for password in user['passwords']:
            self.assertNotIn('salt', password)

    def test_support_user(self):
        user = models.SupportUser(NEW_USER_EXAMPLE)
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)
        for password in user['passwords']:
            self.assertNotIn('salt', password)

    def test_support_dashboard_user(self):
        user = models.SupportDashboardUser(NEW_DASHBOARD_USER_EXAMPLE)
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)
        for password in user['passwords']:
            self.assertNotIn('salt', password)

    def test_support_signup_user(self):
        user = models.SupportSignupUser(NEW_SIGNUP_USER_EXAMPLE)
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)
        for password in user['passwords']:
            self.assertNotIn('salt', password)
