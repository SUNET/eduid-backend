__author__ = 'leifj'

from eduid_am.celery import celery, get_attribute_manager
from eduid_am.tasks import update_attributes
from eduid_am.testing import MongoTestCase
from bson import ObjectId


class UserBDTestCase(MongoTestCase):
    """
    This testcase sets up an AttributeManager instance and sends a message to an internally defined plugin that
    transforms 'uid' to its urn:oid representation.
    """

    def setUp(self):
        """
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

#        am.registry.update(test=plugin)
#
#        db = am.conn.get_database('test')
#
#        _id = ObjectId()
#        assert(db['user'].insert({'_id': _id, 'uid': 'vlindeman'}) == _id)
#
#        update_attributes.delay(app_name='test', obj_id = _id)
#
#        adb = am.conn.get_database(settings['MONGO_DBNAME'])
#        attrs = adb['attributes'].find_one({'_id': _id})
#        assert(attrs['eppn'] == 'vlindeman@eduid.se')
#        user = am.get_user_by_field('eppn', 'vlindeman@eduid.se')
#        assert(user['_id'] == attrs['_id'])
#
