from http import HTTPStatus
from typing import Any

from eduid.scimapi.testing import ScimApiTestCase


class TestStatus(ScimApiTestCase):
    def test_status_healthy_ok(self) -> None:
        response = self.client.get("/status/healthy")
        assert response.status_code == HTTPStatus.OK

    def test_status_ping(self) -> None:
        response = self.client.get("/status/ping")
        assert response.status_code == HTTPStatus.OK
        assert response.content == b""


class TestStatusNeo4jFallbackDisabled(ScimApiTestCase):
    """
    Regression test for check_neo4j (src/eduid/scimapi/routers/utils/status.py): with
    neo4j_fallback=False, ScimApiGroupDB.graphdb is None. check_neo4j must treat that as
    healthy rather than raising - an unhandled AttributeError there would, after repeated
    failing /status/healthy polls, eventually make check_restart's 120s terminate budget call
    sys.exit(1), killing the whole scimapi process in exactly the configuration this
    migration's final step asks operators to run.
    """

    def _get_config(self) -> dict[str, Any]:
        config = super()._get_config()
        config["neo4j_fallback"] = False
        return config

    def test_status_healthy_ok_without_neo4j(self) -> None:
        assert self.groupdb is not None
        assert self.groupdb.graphdb is None
        response = self.client.get("/status/healthy")
        assert response.status_code == HTTPStatus.OK
