from __future__ import annotations

from collections.abc import Iterator

import pytest

from eduid.graphdb.testing import Neo4jTemporaryInstance
from eduid.userdb.testing import MongoTemporaryInstance
from eduid.webapp.common.session.testing import RedisTemporaryInstance


@pytest.fixture(scope="session")
def mongo_instance() -> Iterator[MongoTemporaryInstance]:
    """One MongoDB container per test session (i.e. per pytest-xdist worker)."""
    instance = MongoTemporaryInstance(max_retry_seconds=60)
    yield instance
    instance.shutdown()


@pytest.fixture(scope="session")
def redis_instance() -> Iterator[RedisTemporaryInstance]:
    """One Redis container per test session (i.e. per pytest-xdist worker)."""
    # 120s: multiple workers start Redis containers simultaneously, 60s is too tight
    instance = RedisTemporaryInstance(max_retry_seconds=120)
    yield instance
    instance.shutdown()


@pytest.fixture(scope="session")
def neo4j_instance() -> Iterator[Neo4jTemporaryInstance]:
    """One Neo4j container per test session (i.e. per pytest-xdist worker)."""
    # 240s: Neo4j is heavy and slow to start, especially under parallel load
    instance = Neo4jTemporaryInstance(max_retry_seconds=240)
    yield instance
    instance.shutdown()
