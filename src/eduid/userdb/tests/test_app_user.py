from unittest import TestCase

from pydantic import ValidationError

from eduid.userdb import User
from eduid.userdb.credentials import CredentialList
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.fixtures.users import UserFixtures


class TestAppUser(TestCase):
    users: UserFixtures
    user_data: TUserDbDocument

    def setUp(self):
        _users = UserFixtures()
        self.user = _users.new_user_example
        self.user_data = self.user.to_dict()

    def test_proper_user(self):
        user = User.from_dict(data=self.user_data)
        self.assertEqual(user.user_id, self.user_data["_id"])
        self.assertEqual(user.eppn, self.user_data["eduPersonPrincipalName"])

    def test_proper_new_user(self):
        user = User(user_id=self.user.user_id, eppn=self.user.eppn, credentials=self.user.credentials)
        self.assertEqual(user.user_id, self.user.user_id)
        self.assertEqual(user.eppn, self.user.eppn)

    def test_missing_id(self):
        user = User(eppn=self.user.eppn, credentials=self.user.credentials)
        self.assertNotEqual(user.user_id, self.user.user_id)

    def test_missing_eppn(self):
        _data = self.user.to_dict()
        _data.pop("eduPersonPrincipalName")
        with self.assertRaises(ValidationError):
            User.from_dict(_data)
