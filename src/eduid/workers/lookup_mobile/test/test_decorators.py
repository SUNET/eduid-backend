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
        def find_mobiles_by_nin(
            self: TestTransactionAudit, national_identity_number: str, number_region: str | None = None
        ) -> list[str]:
            return ["list", "of", "mobile_numbers"]

        find_mobiles_by_nin(self, "200202025678")
        c = self.db["transaction_audit"]
        result = c.find()
        assert c.count_documents({}) == 1
        hit = result.next()
        assert hit["data"]["national_identity_number"] == "200202025678"
        assert hit["data"]["data_returned"]
        c.delete_many({})  # Clear database

        @TransactionAudit()
        def find_nin_by_mobile(self: TestTransactionAudit, mobile_number: str) -> str:
            return "200202025678"

        find_nin_by_mobile(self, "+46701740699")
        c = self.db["transaction_audit"]
        result = c.find()
        assert c.count_documents({}) == 1
        hit = result.next()
        assert hit["data"]["mobile_number"] == "+46701740699"
        assert hit["data"]["data_returned"]
        c.delete_many({})  # Clear database

    def test_failed_transaction_audit(self) -> None:
        @TransactionAudit()
        def find_mobiles_by_nin(
            self: TestTransactionAudit, national_identity_number: str, number_region: str | None = None
        ) -> list:
            return []

        find_mobiles_by_nin(self, "200202025678")
        c = self.db["transaction_audit"]
        result = c.find()
        assert c.count_documents({}) == 1
        assert not result.next()["data"]["data_returned"]
        c.delete_many({})  # Clear database

        @TransactionAudit()
        def find_nin_by_mobile(self: TestTransactionAudit, mobile_number: str) -> None:
            return

        find_nin_by_mobile(self, "+46701740699")
        c = self.db["transaction_audit"]
        result = c.find()
        assert c.count_documents({}) == 1
        assert not result.next()["data"]["data_returned"]
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
        assert c.count_documents({}) == 0

        TransactionAudit.enable()

        @TransactionAudit()
        def no_name2(self: TestTransactionAudit) -> dict[str, str]:
            return {"baka": "kaka"}

        no_name2(self)
        c.find()
        assert c.count_documents({}) == 1
