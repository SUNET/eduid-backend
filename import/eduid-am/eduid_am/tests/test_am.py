from __future__ import absolute_import

from dataclasses import dataclass
from typing import Any, Dict

from bson import ObjectId

import eduid_userdb
from eduid_common.config.workers import AmConfig
from eduid_userdb.exceptions import UserDoesNotExist

from eduid_am.ams.common import AttributeFetcher
from eduid_am.testing import AMTestCase

__author__ = 'leifj'


@dataclass
class AmTestUser(eduid_userdb.User):
    """
    User class for the 'test' plugin below.
    """

    uid: str = ''


class AmTestUserDb(eduid_userdb.UserDB):
    """
    UserDB for the 'test' plugin below.
    """

    UserClass = AmTestUser


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

    def get_user_db(self, uri):
        return AmTestUserDb(uri, db_name='eduid_am_test')

    def fetch_attrs(self, user_id):
        user = self.private_db.get_user_by_id(user_id)
        if user is None:
            raise UserDoesNotExist("No user matching _id={!r}".format(user_id))

        # Transfer all attributes except `uid' from the test plugins database.
        # Transform eduPersonPrincipalName on the way to make it clear that the
        # update was done using this code.
        res = user.to_dict()
        res['eduPersonPrincipalName'] = f"{user.uid}-{user.uid}"
        del res['uid']
        attributes = {'$set': res}
        return attributes


class BadAttributeFetcher(FakeAttributeFetcher):
    """
    Returns a bad operations dict.
    """

    def fetch_attrs(self, user_id):
        res = super().fetch_attrs(user_id)
        res['notanoperator'] = 'test'
        return res


class MessageTest(AMTestCase):
    """
    This testcase sets up an AttributeManager instance and sends a message to an internally defined plugin that
    transforms 'uid' to its urn:oid representation.
    """

    def setUp(self):
        super().setUp(want_mongo_uri=True)
        self.private_db = AmTestUserDb(db_uri=self.tmp_db.uri, db_name='eduid_am_test')
        # register fake AMP plugin named 'test'
        AmConfig(app_name='message_test', mongo_uri=self.tmp_db.uri)
        self.am.af_registry['test'] = FakeAttributeFetcher(AmConfig(app_name='message_test', mongo_uri=self.tmp_db.uri))
        # register fake AMP plugin named 'bad'
        self.am.af_registry['bad'] = BadAttributeFetcher(AmConfig(app_name='message_test', mongo_uri=self.tmp_db.uri))

    def test_insert(self):
        """
        This simulates the 'test' application that keeps its own data in the 'user' collection in the 'test' DB
        and sends a message notifying the attribute manager instance (am) about a new entry in its dataset thereby
        calling the plugin (above) which is registered with the am in the test setup below.
        """
        _id = ObjectId()
        with self.assertRaises(eduid_userdb.exceptions.UserDoesNotExist):
            self.amdb.get_user_by_id(_id)

        userdoc = {
            '_id': _id,
            'eduPersonPrincipalName': 'foooo-baaar',
            'uid': 'teste',
            'passwords': [{'id': ObjectId('112345678901234567890123'), 'salt': '$NDNv1H1$9c81...545$32$32$',}],
        }
        test_user = AmTestUser.from_dict(userdoc)
        # Save the user in the eduid_am_test database
        self.private_db.save(test_user)

        # It is important to not import eduid_am.tasks before the Celery config has been
        # set up (done in MongoTestCase.setUp()). Since Celery uses decorators, it will
        # have instantiated AttributeManagers without the right config if the import is
        # done prior to the Celery app configuration.
        from eduid_am.tasks import update_attributes

        update_attributes.delay(app_name='test', user_id=str(_id))

        # verify the user has been propagated to the amdb
        am_user = self.amdb.get_user_by_id(_id)
        self.assertEqual(am_user.eppn, 'teste-teste')

    def test_update(self):
        """
        This simulates the 'test' application that keeps its own data in the 'user' collection in the 'test' DB
        and sends a message notifying the attribute manager instance (am) about a new entry in its dataset thereby
        calling the plugin (above) which is registered with the am in the test setup below.
        """
        _id = ObjectId()

        userdoc = {
            '_id': _id,
            'eduPersonPrincipalName': 'foooo-baaar',
            'uid': 'teste',
            'passwords': [{'id': ObjectId('112345678901234567890123'), 'salt': '$NDNv1H1$9c81...545$32$32$',}],
        }
        test_user = AmTestUser.from_dict(userdoc)
        # Save the user in the private database
        self.private_db.save(test_user)
        # Save the user in the central database
        user_dict = test_user.to_dict()
        del user_dict['uid']
        central_user = eduid_userdb.User.from_dict(user_dict)
        self.amdb.save(central_user, check_sync=False)

        am_user = self.amdb.get_user_by_id(_id)
        self.assertNotEqual(am_user.eppn, 'teste-teste')

        # It is important to not import eduid_am.tasks before the Celery config has been
        # set up (done in MongoTestCase.setUp()). Since Celery uses decorators, it will
        # have instantiated AttributeManagers without the right config if the import is
        # done prior to the Celery app configuration.
        from eduid_am.tasks import update_attributes

        update_attributes.delay(app_name='test', user_id=str(_id))

        # verify the user has been propagated to the amdb
        am_user = self.amdb.get_user_by_id(_id)
        self.assertEqual(am_user.eppn, 'teste-teste')

    def test_bad_operator(self):
        _id = ObjectId()

        userdoc = {
            '_id': _id,
            'eduPersonPrincipalName': 'foooo-baaar',
            'uid': 'teste',
            'passwords': [{'id': ObjectId('112345678901234567890123'), 'salt': '$NDNv1H1$9c81...545$32$32$',}],
        }
        test_user = AmTestUser.from_dict(userdoc)
        # Save the user in the private database
        self.private_db.save(test_user)
        # Save the user in the central database
        user_dict = test_user.to_dict()
        del user_dict['uid']
        central_user = eduid_userdb.User.from_dict(user_dict)
        self.amdb.save(central_user, check_sync=False)

        am_user = self.amdb.get_user_by_id(_id)
        self.assertNotEqual(am_user.eppn, 'teste-teste')

        # It is important to not import eduid_am.tasks before the Celery config has been
        # set up (done in MongoTestCase.setUp()). Since Celery uses decorators, it will
        # have instantiated AttributeManagers without the right config if the import is
        # done prior to the Celery app configuration.
        from eduid_am.tasks import update_attributes

        with self.assertRaises(eduid_userdb.exceptions.EduIDDBError):
            update_attributes.delay(app_name='bad', user_id=str(_id))
