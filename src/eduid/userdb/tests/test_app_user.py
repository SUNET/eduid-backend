from datetime import datetime
from unittest import TestCase

from pydantic import ValidationError

from eduid.userdb import User
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.fixtures.users import UserFixtures


class TestAppUser(TestCase):
    users: UserFixtures
    user_data: TUserDbDocument

    def setUp(self) -> None:
        _users = UserFixtures()
        self.user = _users.new_user_example
        self.user_data = self.user.to_dict()

    def test_proper_user(self) -> None:
        user = User.from_dict(data=self.user_data)
        self.assertEqual(user.user_id, self.user_data["_id"])
        self.assertEqual(user.eppn, self.user_data["eduPersonPrincipalName"])

    def test_proper_new_user(self) -> None:
        user = User(user_id=self.user.user_id, eppn=self.user.eppn, credentials=self.user.credentials)
        self.assertEqual(user.user_id, self.user.user_id)
        self.assertEqual(user.eppn, self.user.eppn)

    def test_missing_id(self) -> None:
        user = User(eppn=self.user.eppn, credentials=self.user.credentials)
        self.assertNotEqual(user.user_id, self.user.user_id)

    def test_missing_eppn(self) -> None:
        _data = self.user.to_dict()
        _data.pop("eduPersonPrincipalName")
        with self.assertRaises(ValidationError):
            User.from_dict(_data)

    def test_identities_created_ts_true(self) -> None:
        _data = self.user.to_dict()
        _data["identities"][0]["created_ts"] = True
        user = User.from_dict(_data)
        identity = user.identities.find(_data["identities"][0]["identity_type"])
        assert identity
        assert isinstance(identity.created_ts, datetime) is True

    def test_locked_identity_created_ts_true(self) -> None:
        _data = self.user.to_dict()
        _data["locked_identity"][0]["created_ts"] = True
        user = User.from_dict(_data)
        locked_identity = user.locked_identity.find(_data["locked_identity"][0]["identity_type"])
        assert locked_identity
        assert isinstance(locked_identity.created_ts, datetime) is True
