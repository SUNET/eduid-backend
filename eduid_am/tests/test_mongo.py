from . import MongoTestCase

__author__ = 'leifj'


class MessageTest(MongoTestCase):

    def testUse(self):
        db = self.conn['test']
        c = db['test']
        obj_id = c.insert({'baka': 'kaka'})
        doc = c.find_one({'_id': obj_id})
        assert(doc['baka'] == 'kaka')
