from eduid_userdb.data_samples import (NEW_USER_EXAMPLE,
                                      NEW_SIGNUP_USER_EXAMPLE,
                                      NEW_COMPLETED_SIGNUP_USER_EXAMPLE,
                                      NEW_DASHBOARD_USER_EXAMPLE)
from eduid_userdb.data_samples import OLD_USER_EXAMPLE, OLD_VERIFICATIONS_EXAMPLE
from eduid_userdb import User
from eduid_userdb.signup import SignupUser
from eduid_userdb.support import models

from unittest import TestCase


class TestSupportUsers(TestCase):

    def test_old_support_user(self):
        user = models.SupportUserFilter(User(data=OLD_USER_EXAMPLE).to_dict())
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)
        for password in user['passwords']:
            self.assertNotIn('salt', password)

    def test_support_user(self):
        user = models.SupportUserFilter(User(data=NEW_USER_EXAMPLE).to_dict())
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)
        for password in user['passwords']:
            self.assertNotIn('salt', password)

    def test_support_signup_user(self):
        user = models.SupportSignupUserFilter(SignupUser(data=NEW_SIGNUP_USER_EXAMPLE).to_dict())
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)
        for password in user['passwords']:
            self.assertNotIn('salt', password)

    def test_support_completed_signup_user(self):
        user = models.SupportSignupUserFilter(SignupUser(data=NEW_COMPLETED_SIGNUP_USER_EXAMPLE).to_dict())
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)

        """
        This should pass without an exception being thrown in GenericFilterDict.
        The assertion is here only for good measure to make sure that the
        right example data is being used.
        """
        self.assertTrue(len(user.get('pending_mail_address')) == 0)

        for password in user['passwords']:
            self.assertNotIn('salt', password)
