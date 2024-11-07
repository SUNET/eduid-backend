from unittest import TestCase

from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.support import models


class TestSupportUsers(TestCase):
    def setUp(self) -> None:
        self.users = UserFixtures()

    def test_support_user(self) -> None:
        user = models.SupportUserFilter(self.users.new_user_example.to_dict())
        self.assertNotIn("_id", user)
        self.assertNotIn("letter_proofing_data", user)
        for password in user["passwords"]:
            self.assertNotIn("salt", password)

    def test_support_signup_user(self) -> None:
        user = models.SupportSignupUserFilter(self.users.new_signup_user_example.to_dict())
        self.assertNotIn("_id", user)
        self.assertNotIn("letter_proofing_data", user)
        for password in user["passwords"]:
            self.assertNotIn("salt", password)

    def test_support_completed_signup_user(self) -> None:
        user = models.SupportSignupUserFilter(self.users.new_completed_signup_user_example.to_dict())
        self.assertNotIn("_id", user)
        self.assertNotIn("letter_proofing_data", user)

        """
        This should pass without an exception being thrown in GenericFilterDict.
        The assertion is here only for good measure to make sure that the
        right example data is being used.
        """
        pending = user.get("pending_mail_address")
        assert pending is not None
        self.assertTrue(len(pending) == 0)

        for password in user["passwords"]:
            self.assertNotIn("salt", password)

    def test_support_user_authn_info(self) -> None:
        raw_data = {
            "_id": "5c5b027c20d6b6000db13187",
            "fail_count": {"201902": 1, "201903": 0},
            "last_credential_ids": ["5c5b02c420d6b6000db1318a"],
            "success_count": {"201902": 77, "201903": 17},
            "success_ts": "2019-03-04T16:00:35.466Z",
        }

        user_authn_info = models.UserAuthnInfo(raw_data)
        self.assertNotIn("_id", user_authn_info)
        self.assertNotIn("last_credential_ids", user_authn_info)
        self.assertEqual(len(user_authn_info["fail_count"].keys()), 1)
