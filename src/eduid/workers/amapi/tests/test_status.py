from http import HTTPStatus

from eduid.workers.amapi.testing import TestAMBase


class TestStatus(TestAMBase):
    def test_status_healthy_ok(self) -> None:
        response = self.client.get(url="/status/healthy")
        assert response.status_code == HTTPStatus.OK

    def test_status_ping(self) -> None:
        response = self.client.get(url="/status/ping")
        assert response.status_code == HTTPStatus.OK
        assert response.content == b""
