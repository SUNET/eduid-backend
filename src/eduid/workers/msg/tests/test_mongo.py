from eduid.userdb.db.base import TUserDbDocument
from eduid.workers.msg.testing import MsgMongoTestCase


class MessageTest(MsgMongoTestCase):
    def setUp(self) -> None:  # type: ignore[override]
        super().setUp()

    def test_mongo(self) -> None:
        db = self.tmp_db.conn["test"]
        c = db["test"]
        id = c.insert_one(TUserDbDocument({"baka": "kaka"})).inserted_id
        doc = c.find_one({"_id": id})
        assert doc
        assert doc["baka"] == "kaka"
