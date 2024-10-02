import logging
from typing import Any

import bson
import pytest

from eduid.common.testing_base import normalised_data
from eduid.userdb import User
from eduid.userdb.db.base import TUserDbDocument
from eduid.userdb.exceptions import UserDoesNotExist, UserOutOfSync
from eduid.userdb.fixtures.passwords import signup_password
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.testing import MongoTestCase
from eduid.userdb.util import format_dict_for_debug

logger = logging.getLogger(__name__)


class TestUserDB(MongoTestCase):
    def setUp(self, *args: Any, **kwargs: Any) -> None:
        self.user = UserFixtures().mocked_user_standard
        super().setUp(am_users=[self.user], **kwargs)

    def test_get_user_by_id(self) -> None:
        """Test get_user_by_id"""
        res = self.amdb.get_user_by_id(self.user.user_id)
        assert res
        assert self.user.user_id == res.user_id

        res = self.amdb.get_user_by_id(str(self.user.user_id))
        assert res
        assert self.user.user_id == res.user_id

        res = self.amdb.get_user_by_id(str(bson.ObjectId()))
        assert res is None

        res = self.amdb.get_user_by_id("not-a-valid-object-id")
        assert res is None

    def test_get_user_by_nin(self) -> None:
        """Test get_user_by_nin"""
        test_user = self.amdb.get_user_by_id(self.user.user_id)
        assert test_user is not None
        test_user.given_name = "Kalle Anka"
        self.amdb.save(test_user)
        assert test_user.identities.nin is not None
        res = self.amdb.get_user_by_nin(test_user.identities.nin.number)
        assert res is not None
        assert test_user.given_name == res.given_name

    def test_remove_user_by_id(self) -> None:
        """Test removing a user from the database

        NOTE: remove_user_by_id() should be moved to SignupUserDb
        """
        test_user = self.amdb.get_user_by_id(self.user.user_id)
        assert test_user
        assert test_user.identities.nin
        res = self.amdb.get_users_by_nin(test_user.identities.nin.number)
        assert normalised_data(res[0].to_dict()) == normalised_data(test_user.to_dict())
        self.amdb.remove_user_by_id(test_user.user_id)
        res = self.amdb.get_users_by_nin(test_user.identities.nin.number)
        assert res == []

    def test_get_user_by_eppn(self) -> None:
        """Test user lookup using eppn"""
        test_user = self.amdb.get_user_by_id(self.user.user_id)
        assert test_user
        res = self.amdb.get_user_by_eppn(test_user.eppn)
        assert test_user.user_id == res.user_id

    def test_get_user_by_eppn_not_found(self) -> None:
        """Test user lookup using unknown"""
        with pytest.raises(UserDoesNotExist):
            self.amdb.get_user_by_eppn("abc123")


class UserMissingMeta(MongoTestCase):
    user: User

    def setUp(self) -> None:  # type: ignore[override]
        self.user = UserFixtures().mocked_user_standard
        super().setUp(am_users=[self.user])

        self._remove_meta_from_user_in_db(self.user)

    def _remove_meta_from_user_in_db(self, user: User) -> None:
        """
        These tests are meant to test new code with old users in the database.

        Remove the user.meta section from the user in the database.
        """
        user_doc = self.amdb._get_document_by_attr("_id", user.user_id)
        assert user_doc is not None
        user_doc.pop("meta")
        self.amdb._coll.replace_one({"_id": user.user_id}, user_doc)

    def test_update_user_new(self) -> None:
        db_user = self.amdb.get_user_by_id(self.user.user_id)
        assert db_user is not None
        logger.debug(f"Loaded user.meta from database:\n{format_dict_for_debug(db_user.meta.dict())}")
        assert db_user is not None
        db_user.given_name = "test"
        self.amdb.save(user=db_user)

    def test_update_user_old(self) -> None:
        db_user = self.amdb.get_user_by_id(self.user.user_id)
        assert db_user
        db_user.given_name = "test"
        self.amdb.save(user=db_user)


class UpdateUser(MongoTestCase):
    def setUp(self, *args: Any, **kwargs: Any) -> None:
        _users = UserFixtures()
        self.user = _users.mocked_user_standard
        super().setUp(am_users=[self.user, _users.mocked_user_standard_2], **kwargs)

    def test_stale_user_meta_version(self) -> None:
        test_user = self.amdb.get_user_by_eppn(self.user.eppn)
        test_user.given_name = "new_given_name"
        test_user.meta.new_version()

        with self.assertRaises(UserOutOfSync):
            self.amdb.save(test_user)

    def test_ok(self) -> None:
        test_user = self.amdb.get_user_by_id(self.user.user_id)
        assert test_user
        test_user.given_name = "new_given_name"

        old_meta_version = test_user.meta.version
        old_modified_ts = test_user.modified_ts

        res = self.amdb.save(test_user)
        assert res.success is True

        db_user = self.amdb.get_user_by_id(test_user.user_id)
        assert db_user
        assert db_user.meta.version != old_meta_version
        assert db_user.modified_ts != old_modified_ts
        assert db_user.given_name == "new_given_name"


class TestUserDB_mail(MongoTestCase):
    def setUp(self, *args: Any, **kwargs: Any) -> None:
        super().setUp(*args, **kwargs)
        data1: TUserDbDocument = TUserDbDocument(
            {
                "_id": bson.ObjectId(),
                "eduPersonPrincipalName": "mail-test1",
                "mail": "test@gmail.com",
                "mailAliases": [{"email": "test@gmail.com", "verified": True}],
                "passwords": [signup_password.to_dict()],
            }
        )

        data2: TUserDbDocument = TUserDbDocument(
            {
                "_id": bson.ObjectId(),
                "eduPersonPrincipalName": "mail-test2",
                "mailAliases": [
                    {"email": "test2@gmail.com", "primary": True, "verified": True},
                    {"email": "test@gmail.com", "verified": False},
                ],
                "passwords": [signup_password.to_dict()],
            }
        )

        self.user1 = User.from_dict(data1)
        self.user2 = User.from_dict(data2)

        self.amdb.save(self.user1)
        self.amdb.save(self.user2)

    def test_get_user_by_mail(self) -> None:
        test_user = self.amdb.get_user_by_id(self.user1.user_id)
        assert test_user
        assert test_user.mail_addresses.primary
        res = self.amdb.get_user_by_mail(test_user.mail_addresses.primary.email)
        assert res
        assert test_user.user_id == res.user_id

    def test_get_user_by_mail_unknown(self) -> None:
        """Test searching for unknown e-mail address"""
        assert self.amdb.get_user_by_mail("abc123@example.edu") is None

    def test_get_user_by_mail_multiple(self) -> None:
        res = self.amdb.get_users_by_mail("test@gmail.com")
        ids = [x.user_id for x in res]
        assert ids == [self.user1.user_id]

        res = self.amdb.get_users_by_mail("test@gmail.com", include_unconfirmed=True)
        ids = [x.user_id for x in res]
        assert ids == [self.user1.user_id, self.user2.user_id]


class TestUserDB_phone(MongoTestCase):
    def setUp(self, *args: Any, **kwargs: Any) -> None:
        super().setUp(*args, **kwargs)
        data1: TUserDbDocument = TUserDbDocument(
            {
                "_id": bson.ObjectId(),
                "eduPersonPrincipalName": "phone-test1",
                "mail": "kalle@example.com",
                "phone": [
                    {"number": "+11111111111", "primary": True, "verified": True},
                    {"number": "+22222222222", "primary": False, "verified": True},
                ],
                "passwords": [signup_password.to_dict()],
            }
        )
        data2: TUserDbDocument = TUserDbDocument(
            {
                "_id": bson.ObjectId(),
                "eduPersonPrincipalName": "phone-test2",
                "mail": "anka@example.com",
                "phone": [
                    {"number": "+11111111111", "primary": True, "verified": False},
                    {"number": "+22222222222", "primary": False, "verified": False},
                    {"number": "+33333333333", "primary": False, "verified": False},
                ],
                "passwords": [signup_password.to_dict()],
            }
        )

        self.user1 = User.from_dict(data1)
        self.user2 = User.from_dict(data2)
        self.amdb.save(self.user1)
        self.amdb.save(self.user2)

    def test_get_user_by_phone(self) -> None:
        test_user = self.amdb.get_user_by_id(self.user1.user_id)
        assert test_user
        assert test_user.phone_numbers.primary
        res = self.amdb.get_user_by_phone(test_user.phone_numbers.primary.number)
        assert res
        assert res.user_id == test_user.user_id

        res = self.amdb.get_user_by_phone("+22222222222")
        assert res
        assert res.user_id == test_user.user_id

        assert self.amdb.get_user_by_phone("+33333333333") is None

        res_list = self.amdb.get_users_by_phone("+33333333333", include_unconfirmed=True)
        assert [x.user_id for x in res_list] == [self.user2.user_id]

    def test_get_user_by_phone_unknown(self) -> None:
        """Test searching for unknown e-phone address"""
        assert self.amdb.get_user_by_phone("abc123@example.edu") is None

    def test_get_user_by_phone_multiple(self) -> None:
        res = self.amdb.get_users_by_phone("+11111111111")
        ids = [x.user_id for x in res]
        assert ids == [self.user1.user_id]

        res = self.amdb.get_users_by_phone("+11111111111", include_unconfirmed=True)
        ids = [x.user_id for x in res]
        assert ids == [self.user1.user_id, self.user2.user_id]


class TestUserDB_nin(MongoTestCase):
    # TODO: Keep for a while to make sure the conversion to identities work as expected
    def setUp(self, *args: Any, **kwargs: Any) -> None:
        super().setUp(*args, **kwargs)
        data1: TUserDbDocument = TUserDbDocument(
            {
                "_id": bson.ObjectId(),
                "eduPersonPrincipalName": "nin-test1",
                "mail": "kalle@example.com",
                "nins": [
                    {"number": "11111111111", "primary": True, "verified": True},
                ],
                "passwords": [signup_password.to_dict()],
            }
        )
        data2: TUserDbDocument = TUserDbDocument(
            {
                "_id": bson.ObjectId(),
                "eduPersonPrincipalName": "nin-test2",
                "mail": "anka@example.com",
                "nins": [
                    {"number": "22222222222", "primary": True, "verified": True},
                ],
                "passwords": [signup_password.to_dict()],
            }
        )
        data3: TUserDbDocument = TUserDbDocument(
            {
                "_id": bson.ObjectId(),
                "eduPersonPrincipalName": "nin-test3",
                "mail": "anka@example.com",
                "nins": [
                    {"number": "33333333333", "primary": False, "verified": False},
                ],
                "passwords": [signup_password.to_dict()],
            }
        )

        self.user1 = User.from_dict(data1)
        self.user2 = User.from_dict(data2)
        self.user3 = User.from_dict(data3)

        self.amdb.save(self.user1)
        self.amdb.save(self.user2)
        self.amdb.save(self.user3)

    def test_get_user_by_nin(self) -> None:
        test_user = self.amdb.get_user_by_id(self.user1.user_id)
        assert test_user
        assert test_user.identities.nin
        res = self.amdb.get_user_by_nin(test_user.identities.nin.number)
        assert res
        assert res.user_id == test_user.user_id, "alpha"

        res = self.amdb.get_user_by_nin("11111111111")
        assert res
        assert res.user_id == test_user.user_id, "beta"

        res = self.amdb.get_user_by_nin("22222222222")
        assert res
        assert res.user_id == self.user2.user_id, "gamma"

        assert self.amdb.get_user_by_nin("33333333333") is None, "delta"

        res_list = self.amdb.get_users_by_nin("33333333333", include_unconfirmed=True)
        assert [x.user_id for x in res_list] == [self.user3.user_id], "epsilon"

    def test_get_user_by_nin_unknown(self) -> None:
        """Test searching for unknown e-nin address"""
        assert self.amdb.get_user_by_nin("77777777777") is None

    def test_get_user_by_nin_multiple(self) -> None:
        # create another user with nin 33333333333, this one verified
        data4 = TUserDbDocument(
            {
                "_id": bson.ObjectId(),
                "eduPersonPrincipalName": "nin-test4",
                "mail": "anka@example.com",
                "nins": [
                    {"number": "33333333333", "primary": True, "verified": True},
                ],
                "passwords": [signup_password.to_dict()],
            }
        )
        user4 = User.from_dict(data4)
        self.amdb.save(user4)

        res = self.amdb.get_users_by_nin("33333333333")
        ids = [x.user_id for x in res]
        assert ids == [user4.user_id]

        res = self.amdb.get_users_by_nin("33333333333", include_unconfirmed=True)
        assert [x.user_id for x in res] == [self.user3.user_id, user4.user_id]
