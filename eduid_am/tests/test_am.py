__author__ = 'leifj'

from eduid_am.celery import celery, get_attribute_manager
from eduid_am.tasks import update_attributes
from eduid_am.tests import MongoTestCase
from bson import ObjectId


def plugin(db, user_id):
    doc = db['user'].find_one({'_id': ObjectId(user_id)})
    return {'eppn': "%s@eduid.se" % doc['uid']}


class MessageTest(MongoTestCase):
    """
    This testcase sets up an AttributeManager instance and sends a message to an internally defined plugin that
    transforms 'uid' to its urn:oid representation.
    """

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
        }

        celery.conf.update(settings)
        am = get_attribute_manager(celery)

        am.registry.update(test=plugin)

        db = am.conn.get_database('test')

        id = ObjectId()
        assert(db['user'].insert({'_id': id, 'uid': 'vlindeman'}) == id)

        update_attributes.delay(app_name='test', user_id=id)

        adb = am.conn.get_database('am')
        attrs = adb['attributes'].find_one({'_id': id})
        assert(attrs['eppn'] == 'vlindeman@eduid.se')
        user = am.get_user_by_field('eppn', 'vlindeman@eduid.se')
        assert(user['_id'] == attrs['_id'])
