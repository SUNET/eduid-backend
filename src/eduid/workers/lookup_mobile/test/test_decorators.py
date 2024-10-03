__author__ = "lundberg"


from eduid.common.config.workers import MsgConfig
from eduid.userdb.testing import SetupConfig
from eduid.workers.lookup_mobile.decorators import TransactionAudit
from eduid.workers.lookup_mobile.testing import LookupMobileMongoTestCase


class TestTransactionAudit(LookupMobileMongoTestCase):
    def setUp(self, config: SetupConfig | None = None) -> None:
        super().setUp(config=config)
        # need to set self.mongo_uri and db for the TransactionAudit decorator
        self.conf = MsgConfig(app_name="testing", mongo_uri=self.tmp_db.uri)
        self.db = self.tmp_db.conn["eduid_lookup_mobile"]

        self.transaction_audit = True

    def test_successfull_transaction_audit(self) -> None:
        @TransactionAudit()
        def find_mobiles_by_NIN(
            self: TestTransactionAudit, national_identity_number: str, number_region: str | None = None
        ) -> list[str]:
            return ["list", "of", "mobile_numbers"]

        find_mobiles_by_NIN(self, "200202025678")
        c = self.db["transaction_audit"]
        result = c.find()
        self.assertEqual(c.count_documents({}), 1)
        hit = result.next()
        self.assertEqual(hit["data"]["national_identity_number"], "200202025678")
        self.assertTrue(hit["data"]["data_returned"])
        c.delete_many({})  # Clear database

        @TransactionAudit()
        def find_NIN_by_mobile(self: TestTransactionAudit, mobile_number: str) -> str:
            return "200202025678"

        find_NIN_by_mobile(self, "+46701740699")
        c = self.db["transaction_audit"]
        result = c.find()
        self.assertEqual(c.count_documents({}), 1)
        hit = result.next()
        self.assertEqual(hit["data"]["mobile_number"], "+46701740699")
        self.assertTrue(hit["data"]["data_returned"])
        c.delete_many({})  # Clear database

    def test_failed_transaction_audit(self) -> None:
        @TransactionAudit()
        def find_mobiles_by_NIN(
            self: TestTransactionAudit, national_identity_number: str, number_region: str | None = None
        ) -> list:
            return []

        find_mobiles_by_NIN(self, "200202025678")
        c = self.db["transaction_audit"]
        result = c.find()
        self.assertEqual(c.count_documents({}), 1)
        self.assertFalse(result.next()["data"]["data_returned"])
        c.delete_many({})  # Clear database

        @TransactionAudit()
        def find_NIN_by_mobile(self: TestTransactionAudit, mobile_number: str) -> None:
            return

        find_NIN_by_mobile(self, "+46701740699")
        c = self.db["transaction_audit"]
        result = c.find()
        self.assertEqual(c.count_documents({}), 1)
        self.assertFalse(result.next()["data"]["data_returned"])
        c.delete_many({})  # Clear database

    def test_transaction_audit_toggle(self) -> None:
        c = self.db["transaction_audit"]
        c.delete_many({})  # Clear database
        TransactionAudit.disable()

        @TransactionAudit()
        def no_name(self: TestTransactionAudit) -> dict[str, str]:
            return {"baka": "kaka"}

        no_name(self)

        c.find()
        self.assertEqual(c.count_documents({}), 0)

        TransactionAudit.enable()

        @TransactionAudit()
        def no_name2(self: TestTransactionAudit) -> dict[str, str]:
            return {"baka": "kaka"}

        no_name2(self)
        c.find()
        self.assertEqual(c.count_documents({}), 1)
