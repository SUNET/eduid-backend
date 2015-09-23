from eduid_userdb.testing import MongoTestCase
from eduid_msg.tests import mock_celery, mock_get_attribute_manager


class MessageTest(MongoTestCase):

    def setUp(self):
        super(MessageTest, self).setUp(celery=mock_celery(), get_attribute_manager=mock_get_attribute_manager)

    def test_mongo(self):
        db = self.conn['test']
        c = db['test']
        id = c.insert({'baka': 'kaka'})
        doc = c.find_one({'_id': id})
        assert(doc['baka'] == 'kaka')
