from unittest import TestCase

from eduid_userdb import User
from eduid_userdb.data_samples import (
    NEW_COMPLETED_SIGNUP_USER_EXAMPLE,
    NEW_DASHBOARD_USER_EXAMPLE,
    NEW_SIGNUP_USER_EXAMPLE,
    OLD_USER_EXAMPLE,
    OLD_VERIFICATIONS_EXAMPLE,
)
from eduid_userdb.fixtures.users import new_user_example
from eduid_userdb.signup import SignupUser
from eduid_userdb.support import models


class TestSupportUsers(TestCase):
    def test_old_support_user(self):
        user = models.SupportUserFilter(User.from_dict(data=OLD_USER_EXAMPLE).to_dict())
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)
        for password in user['passwords']:
            self.assertNotIn('salt', password)

    def test_support_user(self):
        user = models.SupportUserFilter(new_user_example.to_dict())
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)
        for password in user['passwords']:
            self.assertNotIn('salt', password)

    def test_support_signup_user(self):
        user = models.SupportSignupUserFilter(SignupUser.from_dict(data=NEW_SIGNUP_USER_EXAMPLE).to_dict())
        self.assertNotIn('_id', user)
        self.assertNotIn('letter_proofing_data', user)
        for password in user['passwords']:
            self.assertNotIn('salt', password)

    def test_support_completed_signup_user(self):
        user = models.SupportSignupUserFilter(SignupUser.from_dict(data=NEW_COMPLETED_SIGNUP_USER_EXAMPLE).to_dict())
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

    def test_support_user_authn_info(self):
        raw_data = {
            '_id': '5c5b027c20d6b6000db13187',
            'fail_count': {'201902': 1, '201903': 0},
            'last_credential_ids': ['5c5b02c420d6b6000db1318a'],
            'success_count': {'201902': 77, '201903': 17},
            'success_ts': '2019-03-04T16:00:35.466Z',
        }

        user_authn_info = models.UserAuthnInfo(raw_data)
        self.assertNotIn('_id', user_authn_info)
        self.assertNotIn('last_credential_ids', user_authn_info)
        self.assertEqual(len(user_authn_info['fail_count'].keys()), 1)
