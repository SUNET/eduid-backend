from http import HTTPStatus

from eduid.userdb.testing import SetupConfig
from eduid.workers.amapi.testing import TestAMBase


class TestStatus(TestAMBase):
    def setUp(self, config: SetupConfig | None = None) -> None:
        super().setUp(config=config)

    def test_status_healthy_ok(self) -> None:
        response = self.client.get(url="/status/healthy")
        assert response.status_code == HTTPStatus.OK
