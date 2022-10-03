from typing import Dict

from eduid.common.testing_base import CommonTestCase
from eduid.userdb.fixtures.users import new_user_example

from eduid.workers.user_cleaner.app import init_app


class WorkerTest(CommonTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(am_users=[new_user_example])

        self.test_config = self._get_config()

        self.app = init_app(name="test_cleaner", test_config=self.test_config)

    def _get_config(self) -> Dict:
        config = {
            "mongo_uri": self.settings["mongo_uri"],
        }
        return config

    def test_worker_skv(self):
        self.app.run_skv()
