from __future__ import annotations

import logging
import random
from collections.abc import Sequence
from os import environ
from typing import cast

import pytest
from neo4j.exceptions import ServiceUnavailable

from eduid.graphdb.db import Neo4jDB
from eduid.userdb.testing import EduidTemporaryInstance

__author__ = "lundberg"


# Run tests with different Neo4j docker image versions using environment variables
NEO4J_VERSION = environ.get("NEO4J_VERSION", "4.4-enterprise")

logger = logging.getLogger(__name__)
logger.info(f"NEO4J_VERSION={NEO4J_VERSION}")


class Neo4jTemporaryInstance(EduidTemporaryInstance):
    """
    Singleton to manage a temporary Neo4j instance

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.

    """

    _instance: Neo4jTemporaryInstance | None = None
    _http_port: int
    _https_port: int
    _bolt_port: int

    DEFAULT_USERNAME = "neo4j"
    DEFAULT_PASSWORD = "testingtesting"

    def __init__(self, max_retry_seconds: int = 60, neo4j_version: str = NEO4J_VERSION) -> None:
        self._http_port = random.randint(40000, 44999)
        self._https_port = random.randint(45000, 54999)
        self._bolt_port = random.randint(55000, 64999)
        self._docker_name = f"test_neo4j_{self.bolt_port}"
        self._neo4j_version = neo4j_version
        self._host = "localhost"

        super().__init__(max_retry_seconds=max_retry_seconds)

    @property
    def command(self) -> Sequence[str]:
        return [
            "docker",
            "run",
            "--rm",
            "--name",
            f"{self._docker_name}",
            "-p",
            f"{self.http_port}:7474",
            "-p",
            f"{self.https_port}:7473",
            "-p",
            f"{self.bolt_port}:7687",
            "-e",
            f"NEO4J_AUTH={self.DEFAULT_USERNAME}/{self.DEFAULT_PASSWORD}",
            "-e",
            "NEO4J_ACCEPT_LICENSE_AGREEMENT=yes",
            f"neo4j:{self._neo4j_version}",
        ]

    def setup_conn(self) -> bool:
        # Create a candidate connection without overwriting self._conn yet — the driver is lazy
        # so we must run a query to confirm the server is actually ready.
        db_uri = f"bolt://{self.DEFAULT_USERNAME}:{self.DEFAULT_PASSWORD}@{self.host}:{self.bolt_port}"
        candidate = Neo4jDB(db_uri=db_uri, config={"encrypted": False})
        try:
            with candidate.driver.session() as session:
                session.run("MATCH (n) RETURN n")
        except (ServiceUnavailable, ConnectionError) as e:
            logger.error(e)
            candidate.close()  # release driver threads from this failed attempt
            return False
        # Success — close any previous attempt and store the working connection
        if self._conn is not None:
            self._conn.close()
        self._conn = candidate
        return True

    @property
    def conn(self) -> Neo4jDB:
        if self._conn is None:
            raise RuntimeError("Missing temporary Neo4jDB instance")
        return cast(Neo4jDB, self._conn)

    @property
    def host(self) -> str:
        return self._host

    @property
    def http_port(self) -> int:
        return self._http_port

    @property
    def https_port(self) -> int:
        return self._https_port

    @property
    def bolt_port(self) -> int:
        return self._bolt_port

    def purge_db(self) -> None:
        q = """
            MATCH (n)
            DETACH DELETE n
            """
        with self.conn.driver.session() as s:
            s.run(q)
            # Drop constraints and indices
            for constraint in s.run("CALL db.constraints"):
                s.run(f"DROP CONSTRAINT {constraint['name']}")
            for index in s.run("CALL db.indexes"):
                s.run(f"DROP INDEX {index['name']}")


class Neo4jTestCase:
    """
    Base test case that sets up a temporary Neo4j instance
    """

    neo4j_instance: Neo4jTemporaryInstance
    neo4jdb: Neo4jDB

    @pytest.fixture(autouse=True)
    def setup_neo4j(self, neo4j_instance: Neo4jTemporaryInstance) -> None:
        self.neo4j_instance = neo4j_instance
        self.neo4jdb = self.neo4j_instance.conn
        self.neo4j_instance.purge_db()
