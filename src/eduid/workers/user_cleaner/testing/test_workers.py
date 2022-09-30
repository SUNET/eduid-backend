from eduid.common.testing_base import CommonTestCase
from eduid.userdb.fixtures.users import new_user_example

from eduid.workers.user_cleaner.app import new_service, Service


class WorkerTest(CommonTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(am_users=[new_user_example])

        self.service = Service()
        self.service.users = [new_user_example]

    def test_worker_skv(self):
        self.service.worker_skv()
