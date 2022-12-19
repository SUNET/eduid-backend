from unittest import TestCase

from pydantic import ValidationError

from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.signup.user import SignupUser


class TestSignupUser(TestCase):
    def setUp(self):
        self.user = UserFixtures().new_signup_user_example
        self.user_data = self.user.to_dict()

    def test_proper_user(self):
        self.assertEqual(self.user.user_id, self.user_data["_id"])
        self.assertEqual(self.user.eppn, self.user_data["eduPersonPrincipalName"])

    def test_proper_new_user(self):
        user = SignupUser(user_id=self.user.user_id, eppn=self.user.eppn)
        self.assertEqual(user.user_id, self.user.user_id)
        self.assertEqual(user.eppn, self.user.eppn)

    def test_missing_id(self):
        user = SignupUser(eppn=self.user.eppn)
        self.assertNotEqual(user.user_id, self.user.user_id)

    def test_missing_eppn(self):
        with self.assertRaises(ValidationError):
            SignupUser(user_id=self.user.user_id)
