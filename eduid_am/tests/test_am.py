__author__ = 'leifj'

from eduid_am.celery import celery, get_attribute_manager
from eduid_am.tasks import update_attributes
from eduid_userdb.testing import MongoTestCase
from bson import ObjectId

import eduid_userdb

from eduid_userdb.exceptions import UserDoesNotExist


class AmTestUser(eduid_userdb.User):
    """
    User class for the 'test' plugin below.
    """
    def __init__(self, data):
        self.uid = data.pop('uid', None)

        eduid_userdb.User.__init__(self, data = data)

    def to_dict(self, old_userdb_format=False):
        res = eduid_userdb.User.to_dict(self, old_userdb_format=old_userdb_format)
        res['uid'] = self.uid
        return res


class AmTestUserDb(eduid_userdb.UserDB):
    """
    UserDB for the 'test' plugin below.
    """
    UserClass = AmTestUser


def plugin(db, user_id):
    """
    A small fake attribute manager plugin that reads a user and sets the 'eppn'
    attribute to one based on the users _id.

    :param db: User database
    :param user_id: Unique identifier
    :type db: AmTestUserDb
    :type user_id: ObjectId

    :return: update dict
    :rtype: dict
    """
    assert isinstance(db, AmTestUserDb)

    user = db.get_user_by_id(user_id)
    if user is None:
        raise UserDoesNotExist("No user matching _id='%s'" % user_id)

    return {'eduPersonPrincipalName': "%s@eduid.se" % user.uid}


class MessageTest(MongoTestCase):
    """
    This testcase sets up an AttributeManager instance and sends a message to an internally defined plugin that
    transforms 'uid' to its urn:oid representation.
    """
    def setUp(self):
        super(MessageTest, self).setUp(celery, get_attribute_manager)

    def testMessage(self):
        """
        This simulates the 'test' application that keeps its own data in the 'user' collection in the 'test' DB
        and sends a message notifying the attribute manager instance (am) about a new entry in its dataset thereby
        calling the plugin (above) which is registered with the am in the test setup below.
        """
        settings = {
            'BROKER_TRANSPORT': 'memory',
            'BROKER_URL': 'memory://',
            'CELERY_EAGER_PROPAGATES_EXCEPTIONS': True,
            'CELERY_ALWAYS_EAGER': True,
            'CELERY_RESULT_BACKEND': "cache",
            'CELERY_CACHE_BACKEND': 'memory',
            'MONGO_URI': 'mongodb://localhost:%d/' % self.port,
            'MONGO_DBNAME': 'am',
        }

        celery.conf.update(settings)
        am = get_attribute_manager(celery)

        test_db_uri = self.tmp_db.get_uri('eduid_am_test_userdb')
        test_userdb = AmTestUserDb(db_uri = test_db_uri)

        am.userdbs['test'] = test_userdb

        am.registry.update(test=plugin)

        db = self.tmp_db.conn['test']

        _id = ObjectId()
        userdoc = {'_id': _id,
                   'eduPersonPrincipalName': 'foo-bar',
                   'uid': 'vlindeman',
                   }
        test_user = AmTestUser(userdoc)
        test_userdb.save(test_user)

        update_attributes.delay(app_name='test', obj_id = _id)

        am_user = self.amdb.get_user_by_id(_id)
        self.assertEqual(am_user.eppn, 'vlindeman@eduid.se')
