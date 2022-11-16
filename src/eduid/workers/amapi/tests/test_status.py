from eduid.userdb.fixtures.users import new_user_example
from eduid.workers.amapi.tests.test_user import TestAMBase


class TestStatus(TestAMBase):
    def setUp(self, *args, **kwargs):
        super().setUp(am_users=[new_user_example])

    def test_status(self):
        response = self.client.get(url="/status/healthy")
        assert response.status_code == 200
