from typing import Any

from eduid.userdb.user import User
from eduid.workers.msg.decorators import TransactionAudit
from eduid.workers.msg.testing import MsgMongoTestCase


class TestTransactionAudit(MsgMongoTestCase):
    def setUp(self, am_users: list[User] | None = None, init_msg: bool = True) -> None:
        super().setUp(init_msg=init_msg)
        assert self.msg_settings.mongo_uri
        TransactionAudit.enable(self.msg_settings.mongo_uri, db_name="test")

    def test_transaction_audit(self) -> None:
        @TransactionAudit()
        def no_name():
            return {"baka": "kaka"}

        # Invoke transaction logging by calling the function that is decorated with TransactionAudit
        no_name()

        db = self.tmp_db.conn["test"]
        c = db["transaction_audit"]
        result_cursor = c.find({})
        # Check that an audit entry was created
        assert c.count_documents({}) == 1
        # Check the contents
        assert result_cursor.next()["data"]["baka"] == "kaka"

        @TransactionAudit()
        def _get_navet_data(arg1: str, arg2: str):
            return {"baka", "kaka"}

        _get_navet_data("dummy", "1111")
        result = c.find_one({"data": {"identity_number": "1111"}})
        assert result
        self.assertEqual(result["data"]["identity_number"], "1111")

        @TransactionAudit()
        def send_message(
            _self: Any,
            message_type: str,
            reference: str,
            message_dict: str,
            recipient: str,
            template: str,
            language: str,
            subject: str | None = None,
        ):
            return "kaka"

        send_message("dummy", "mm", "reference", "dummy", "2222", "template", "lang")
        result = c.find_one({"data.transaction_id": "kaka"})
        assert result
        self.assertEqual(result["data"]["recipient"], "2222")
        self.assertEqual(result["data"]["audit_reference"], "reference")
        self.assertEqual(result["data"]["template"], "template")

        send_message("dummy", "sms", "reference", "dummy", "3333", "template", "lang")
        result = c.find_one({"data.recipient": "3333"})
        assert result
        self.assertEqual(result["data"]["recipient"], "3333")
        self.assertEqual(result["data"]["audit_reference"], "reference")
        self.assertEqual(result["data"]["template"], "template")

    def test_transaction_audit_toggle(self) -> None:
        db = self.tmp_db.conn["test"]
        c = db["transaction_audit"]
        c.delete_many({})  # Clear database
        TransactionAudit.disable()

        @TransactionAudit()
        def no_name():
            return {"baka": "kaka"}

        no_name()

        c.find({})
        self.assertEqual(c.count_documents({}), 0)

        assert self.msg_settings.mongo_uri
        TransactionAudit.enable(self.msg_settings.mongo_uri)

        @TransactionAudit()
        def no_name2():
            return {"baka": "kaka"}

        no_name2()
        c.find({})
        self.assertEqual(c.count_documents({}), 1)
