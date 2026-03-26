from eduid.userdb.db.base import TUserDbDocument
from eduid.workers.msg.testing import MsgMongoTestCase


class MessageTest(MsgMongoTestCase):
    def test_mongo(self) -> None:
        db = self.tmp_db.conn["test"]
        c = db["test"]
        test_id = c.insert_one(TUserDbDocument({"baka": "kaka"})).inserted_id
        doc = c.find_one({"_id": test_id})
        assert doc
        assert doc["baka"] == "kaka"
