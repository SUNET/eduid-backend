from http import HTTPStatus

from eduid.maccapi.testing import MAccApiTestCase


class TestStatus(MAccApiTestCase):
    def test_status_healthy_ok(self) -> None:
        response = self.client.get("/status/healthy")
        assert response.status_code == HTTPStatus.OK

    def test_status_ping(self) -> None:
        response = self.client.get("/status/ping")
        assert response.status_code == HTTPStatus.OK
        assert response.content == b""
