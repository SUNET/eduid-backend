__author__ = 'leifj'

from . import MONGODB_TEST_PORT
from celery import task
from .. import AttributeManager, update
from . import MongoTestCase
from bson import ObjectId


class MessageTest(MongoTestCase):
    """
    This testcase sets up an AttributeManager instance and sends a message to an internally defined plugin that
    transforms 'uid' to its urn:oid representation.
    """

    def plugin(self, id):
        db = self.conn['test']
        doc = db['user'].find_one({'_id': ObjectId(id)})

        return {'eppn': "%s@eduid.se" % doc['uid']}

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
            '_db': self.conn['am']
        }
        am = AttributeManager(settings)
        am.register('test', self.plugin)
        db = self.conn['test']
        id = ObjectId()
        assert(db['user'].insert({'_id': id, 'uid': 'vlindeman'}) == id)
        update.delay(application='test', id=id)
        adb = self.conn['am']
        attrs = adb['attributes'].find_one({'_id': id})
        assert(attrs['eppn'] == 'vlindeman@eduid.se')