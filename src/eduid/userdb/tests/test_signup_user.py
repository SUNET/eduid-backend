from unittest import TestCase

from pydantic import ValidationError

from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.signup.user import SignupUser


class TestSignupUser(TestCase):
    def setUp(self) -> None:
        self.user = UserFixtures().new_signup_user_example
        self.user_data = self.user.to_dict()

    def test_proper_user(self) -> None:
        self.assertEqual(self.user.user_id, self.user_data["_id"])
        self.assertEqual(self.user.eppn, self.user_data["eduPersonPrincipalName"])

    def test_proper_new_user(self) -> None:
        user = SignupUser(user_id=self.user.user_id, eppn=self.user.eppn)
        self.assertEqual(user.user_id, self.user.user_id)
        self.assertEqual(user.eppn, self.user.eppn)

    def test_missing_id(self) -> None:
        user = SignupUser(eppn=self.user.eppn)
        self.assertNotEqual(user.user_id, self.user.user_id)

    def test_missing_eppn(self) -> None:
        with self.assertRaises(ValidationError):
            SignupUser(user_id=self.user.user_id)  # type: ignore[call-arg]
