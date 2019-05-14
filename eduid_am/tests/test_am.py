from __future__ import absolute_import

from eduid_userdb.testing import MongoTestCase
from bson import ObjectId

from eduid_am.ams.common import AttributeFetcher
import eduid_userdb
from eduid_userdb.exceptions import UserDoesNotExist

__author__ = 'leifj'


class AmTestUser(eduid_userdb.User):
    """
    User class for the 'test' plugin below.
    """
    def __init__(self, data):
        self.uid = data.pop('uid', None)

        eduid_userdb.User.__init__(self, data=data)

    def to_dict(self, old_userdb_format=False):
        res = eduid_userdb.User.to_dict(self, old_userdb_format=old_userdb_format)
        res['uid'] = self.uid
        return res


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

    def __call__(self, user_id):

        user = self.private_db.get_user_by_id(user_id)
        if user is None:
            raise UserDoesNotExist("No user matching _id={!r}".format(user_id))

        # Transfer all attributes except `uid' from the test plugins database.
        # Transform eduPersonPrincipalName on the way to make it clear that the
        # update was done using this code.
        res = user.to_dict(old_userdb_format=True)
        res['eduPersonPrincipalName'] = "{!s}@eduid.se".format(user.uid)
        del res['uid']
        return res


class MessageTest(MongoTestCase):
    """
    This testcase sets up an AttributeManager instance and sends a message to an internally defined plugin that
    transforms 'uid' to its urn:oid representation.
    """
    def setUp(self):
        super(MessageTest, self).setUp(init_am=True, am_settings={'WANT_MONGO_URI': True})

    def testMessage(self):
        """
        This simulates the 'test' application that keeps its own data in the 'user' collection in the 'test' DB
        and sends a message notifying the attribute manager instance (am) about a new entry in its dataset thereby
        calling the plugin (above) which is registered with the am in the test setup below.
        """
        test_context = AmTestUserDb(db_uri=self.tmp_db.uri, db_name='eduid_am_test')

        # register fake AMP plugin named 'test'
        self.am.af_registry['test'] = FakeAttributeFetcher({'MONGO_URI': self.tmp_db.uri})

        _id = ObjectId()
        userdoc = {'_id': _id,
                   'eduPersonPrincipalName': 'foo-bar',
                   'uid': 'vlindeman',
                   'passwords': [{'id': ObjectId('112345678901234567890123'),
                                  'salt': '$NDNv1H1$9c81...545$32$32$',
                                  }],
                   }
        test_user = AmTestUser(userdoc)
        # Save the user in the eduid_am_test database
        test_context.save(test_user)

        # It is important to not import eduid_am.tasks before the Celery config has been
        # set up (done in MongoTestCase.setUp()). Since Celery uses decorators, it will
        # have instantiated AttributeManagers without the right config if the import is
        # done prior to the Celery app configuration.
        from eduid_am.tasks import update_attributes
        update_attributes.delay(app_name='test', obj_id=str(_id))

        # verify the user has been propagated to the amdb
        am_user = self.amdb.get_user_by_id(_id)
        self.assertEqual(am_user.eppn, 'vlindeman@eduid.se')
