from typing import Any

from bson import ObjectId

import eduid.userdb
from eduid.common.config.workers import AmConfig
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.exceptions import UserDoesNotExist
from eduid.userdb.user import User
from eduid.workers.am.ams.common import AttributeFetcher
from eduid.workers.am.common import AmCelerySingleton
from eduid.workers.am.testing import AMTestCase

__author__ = "leifj"


class AmTestUser(eduid.userdb.User):
    """
    User class for the 'test' plugin below.
    """

    uid: str = ""


class AmTestUserDb(eduid.userdb.UserDB[AmTestUser]):
    """
    UserDB for the 'test' plugin below.
    """

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> AmTestUser:
        return AmTestUser.from_dict(data)


class FakeAttributeFetcher(AttributeFetcher):
    """
    A small fake attribute manager plugin that reads a user and sets the 'eppn'
    attribute to one based on the users _id.

    :param context: User database
    :param user_id: Unique identifier
    :type context: AmTestUserDb
    :type user_id: ObjectId

    :return: update dict
    :rtype: dict
    """

    @classmethod
    def get_user_db(cls, uri: str):
        return AmTestUserDb(uri, db_name="eduid_am_test")

    def fetch_attrs(self, user_id: ObjectId) -> dict[str, Any]:
        assert self.private_db
        user: User | None = self.private_db.get_user_by_id(user_id)
        assert isinstance(user, AmTestUser)
        if user is None:
            raise UserDoesNotExist(f"No user matching _id={user_id!r}")

        # Transfer all attributes except `uid' from the test plugins database.
        # Transform eduPersonPrincipalName on the way to make it clear that the
        # update was done using this code.
        res = user.to_dict()
        res["eduPersonPrincipalName"] = f"{user.uid}-{user.uid}"
        del res["uid"]
        attributes = {"$set": res}
        return attributes


class BadAttributeFetcher(FakeAttributeFetcher):
    """
    Returns a bad operations dict.
    """

    def fetch_attrs(self, user_id: ObjectId) -> dict[str, Any]:
        res = super().fetch_attrs(user_id)
        res["notanoperator"] = "test"
        return res


class MessageTest(AMTestCase):
    """
    This testcase sets up an AttributeManager instance and sends a message to an internally defined plugin that
    transforms 'uid' to its urn:oid representation.
    """

    def setUp(self, *args: Any, **kwargs: Any) -> None:
        super().setUp(*args, want_mongo_uri=True, **kwargs)
        self.private_db = AmTestUserDb(db_uri=self.tmp_db.uri, db_name="eduid_am_test")
        # register fake AMP plugin named 'test'
        AmConfig(app_name="message_test", mongo_uri=self.tmp_db.uri)
        AmCelerySingleton.af_registry.add_fetcher(
            "test", FakeAttributeFetcher(AmConfig(app_name="message_test", mongo_uri=self.tmp_db.uri))
        )
        # register fake AMP plugin named 'bad'
        AmCelerySingleton.af_registry.add_fetcher(
            "bad", BadAttributeFetcher(AmConfig(app_name="message_test", mongo_uri=self.tmp_db.uri))
        )

    def test_insert(self) -> None:
        """
        This simulates the 'test' application that keeps its own data in the 'user' collection in the 'test' DB
        and sends a message notifying the attribute manager instance (am) about a new entry in its dataset thereby
        calling the plugin (above) which is registered with the am in the test setup below.
        """
        _id = ObjectId()
        assert not self.amdb.get_user_by_id(_id)

        userdoc = TUserDbDocument(
            {
                "_id": _id,
                "eduPersonPrincipalName": "foooo-baaar",
                "uid": "teste",
                "passwords": [
                    {
                        "id": ObjectId("112345678901234567890123"),
                        "salt": "$NDNv1H1$9c81...545$32$32$",
                    }
                ],
            }
        )
        test_user = AmTestUser.from_dict(userdoc)
        # Save the user in the eduid.workers.am_test database
        self.private_db.save(test_user)

        self.am_relay.request_user_sync(test_user, app_name_override="test")

        # verify the user has been propagated to the amdb
        am_user = self.amdb.get_user_by_id(_id)
        assert am_user
        self.assertEqual(am_user.eppn, "teste-teste")

    def test_update(self) -> None:
        """
        This simulates the 'test' application that keeps its own data in the 'user' collection in the 'test' DB
        and sends a message notifying the attribute manager instance (am) about a new entry in its dataset thereby
        calling the plugin (above) which is registered with the am in the test setup below.
        """
        _id = ObjectId()

        userdoc = TUserDbDocument(
            {
                "_id": _id,
                "eduPersonPrincipalName": "foooo-baaar",
                "uid": "teste",
                "passwords": [
                    {
                        "id": ObjectId("112345678901234567890123"),
                        "salt": "$NDNv1H1$9c81...545$32$32$",
                    }
                ],
            }
        )
        test_user = AmTestUser.from_dict(userdoc)
        # Save the user in the private database
        self.private_db.save(test_user)
        # Save the user in the central database
        user_dict = test_user.to_dict()
        del user_dict["uid"]
        central_user = eduid.userdb.User.from_dict(user_dict)
        self.amdb.save(central_user)

        am_user = self.amdb.get_user_by_id(_id)
        assert am_user
        self.assertNotEqual(am_user.eppn, "teste-teste")

        self.am_relay.request_user_sync(test_user, app_name_override="test")

        # verify the user has been propagated to the amdb
        am_user = self.amdb.get_user_by_id(_id)
        assert am_user
        self.assertEqual(am_user.eppn, "teste-teste")

    def test_bad_operator(self) -> None:
        _id = ObjectId()

        userdoc = TUserDbDocument(
            {
                "_id": _id,
                "eduPersonPrincipalName": "foooo-baaar",
                "uid": "teste",
                "passwords": [
                    {
                        "id": ObjectId("112345678901234567890123"),
                        "salt": "$NDNv1H1$9c81...545$32$32$",
                    }
                ],
            }
        )
        test_user = AmTestUser.from_dict(userdoc)
        # Save the user in the private database
        self.private_db.save(test_user)
        # Save the user in the central database
        user_dict = test_user.to_dict()
        del user_dict["uid"]
        central_user = eduid.userdb.User.from_dict(user_dict)
        self.amdb.save(central_user)

        am_user = self.amdb.get_user_by_id(_id)
        assert am_user
        self.assertNotEqual(am_user.eppn, "teste-teste")

        with self.assertRaises(eduid.userdb.exceptions.EduIDDBError):
            self.am_relay.request_user_sync(test_user, app_name_override="bad")
