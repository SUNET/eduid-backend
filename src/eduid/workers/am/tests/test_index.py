__author__ = "lundberg"

import unittest

from eduid.userdb import UserDB
from eduid.userdb.testing import SetupConfig
from eduid.workers.am.testing import AMTestCase

# TODO: tbd: fix or remove as it is not working yet


@unittest.skip("Not working yet")
class TestIndexes(AMTestCase):
    def setUp(self, config: SetupConfig | None = None) -> None:
        super().setUp(config=config)

    def test_index_setup(self) -> None:
        indexes = {
            # 'index-name': {'key': [('key', 1)], 'param1': True, 'param2': False}
            # http://docs.mongodb.org/manual/reference/method/db.collection.ensureIndex/
            "mail-index-v2": {"key": [("mail", 1)], "unique": True, "sparse": True},
            "eppn-index-v1": {"key": [("eduPersonPrincipalName", 1)], "unique": True},
            "norEduPersonNIN-index-v2": {"key": [("norEduPersonNIN", 1)], "unique": True, "sparse": True},
            "mobile-index-v1": {"key": [("mobile.mobile", 1), ("mobile.verified", 1)]},
            "mailAliases-index-v1": {"key": [("mailAliases.email", 1), ("mailAliases.verified", 1)]},
        }
        db = UserDB(self.settings.mongo_uri)  # type: ignore[call-arg,var-annotated,attr-defined]
        print(db._coll.index_information())
        db.setup_indexes(indexes)
        current_indexes = db._coll.index_information()
        print(current_indexes)
