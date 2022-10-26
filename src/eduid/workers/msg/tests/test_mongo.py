from eduid.workers.msg.testing import MsgMongoTestCase


class MessageTest(MsgMongoTestCase):
    def setUp(self):
        super(MessageTest, self).setUp()

    def test_mongo(self):
        db = self.tmp_db.conn["test"]
        c = db["test"]
        id = c.insert_one({"baka": "kaka"}).inserted_id
        doc = c.find_one({"_id": id})
        assert doc["baka"] == "kaka"
