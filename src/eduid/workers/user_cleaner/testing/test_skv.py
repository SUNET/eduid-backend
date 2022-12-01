from eduid.common.testing_base import CommonTestCase
from eduid.userdb.fixtures.users import new_user_example, new_user_example2, new_unverified_user_example


class WorkerTest(CommonTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(am_users=[new_user_example, new_user_example2, new_unverified_user_example])
