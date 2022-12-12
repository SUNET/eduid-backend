from eduid.workers.amapi.testing import TestAMBase


class TestStatus(TestAMBase):
    def setUp(self):
        super().setUp()

    def test_status_healthy_ok(self):
        response = self.client.get(url="/status/healthy")
        assert response.status_code == 200
