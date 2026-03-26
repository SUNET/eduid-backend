from http import HTTPStatus

import pytest

from eduid.scimapi.testing import ScimApiTestCase

pytestmark = pytest.mark.xdist_group("neo4j")


class TestStatus(ScimApiTestCase):
    def test_status_healthy_ok(self) -> None:
        response = self.client.get("/status/healthy")
        assert response.status_code == HTTPStatus.OK

    def test_status_ping(self) -> None:
        response = self.client.get("/status/ping")
        assert response.status_code == HTTPStatus.OK
        assert response.content == b""
