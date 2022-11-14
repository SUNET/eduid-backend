import time
from typing import Dict

from eduid.common.testing_base import CommonTestCase
from eduid.userdb.fixtures.users import new_user_example, new_user_example2, new_unverified_user_example

from eduid.workers.user_cleaner.app import init_skv
from eduid.workers.user_cleaner.config import WorkerInfo


class WorkerTest(CommonTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(am_users=[new_user_example, new_user_example2, new_unverified_user_example])

        self.test_config = self._get_config()

    def _get_config(self) -> Dict:
        config = {
            "mongo_uri": self.settings["mongo_uri"],
            "test_runs": 4,
            "workers": {
                "skv": WorkerInfo(
                    user_count=10,
                ),
                "ladok": WorkerInfo(
                    user_count=10,
                ),
            },
        }
        return config


class TestSKV(WorkerTest):
    def setUp(self, *args, **kwargs):
        super().setUp()
        self.worker_skv = init_skv(test_config=self.test_config)

    def test_worker_skv(self):
        self.worker_skv.run()
