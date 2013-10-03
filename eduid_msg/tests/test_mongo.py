from . import MongoTestCase


class MessageTest(MongoTestCase):
    def test_mongo(self):
        db = self.conn['test']
        c = db['test']
        id = c.insert({'baka': 'kaka'})
        doc = c.find_one({'_id': id})
        assert(doc['baka'] == 'kaka')
