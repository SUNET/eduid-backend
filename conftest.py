from __future__ import annotations

from collections.abc import Iterator

import pytest

from eduid.graphdb.testing import Neo4jTemporaryInstance
from eduid.userdb.testing import MongoTemporaryInstance
from eduid.webapp.common.session.testing import RedisTemporaryInstance


@pytest.fixture(scope="session")
def mongo_instance() -> Iterator[MongoTemporaryInstance]:
    """One MongoDB container per test session (i.e. per pytest-xdist worker).

    Uses get_instance() so that legacy code still calling MongoTemporaryInstance.get_instance()
    directly (outside of fixture injection) receives the same container this fixture started.

    TODO: Migrate all remaining get_instance() callers to accept this fixture as a parameter,
          then switch back to direct instantiation: MongoTemporaryInstance(max_retry_seconds=60)
    """
    instance = MongoTemporaryInstance.get_instance(max_retry_seconds=60)
    yield instance
    instance.shutdown()


@pytest.fixture(scope="session")
def redis_instance() -> Iterator[RedisTemporaryInstance]:
    """One Redis container per test session (i.e. per pytest-xdist worker).

    Uses get_instance() so that legacy code still calling RedisTemporaryInstance.get_instance()
    directly (outside of fixture injection) receives the same container this fixture started.

    # 120s: multiple workers start Redis containers simultaneously, 60s is too tight

    TODO: Migrate all remaining get_instance() callers to accept this fixture as a parameter,
          then switch back to direct instantiation: RedisTemporaryInstance(max_retry_seconds=120)
    """
    instance = RedisTemporaryInstance.get_instance(max_retry_seconds=120)
    yield instance
    instance.shutdown()


@pytest.fixture(scope="session")
def neo4j_instance() -> Iterator[Neo4jTemporaryInstance]:
    """One Neo4j container per test session.

    Neo4j test files are marked with xdist_group('neo4j') so all Neo4j tests
    run on a single worker — only one container ever starts.

    Uses get_instance() so that legacy code still calling Neo4jTemporaryInstance.get_instance()
    directly (outside of fixture injection, e.g. from update_config() in test_app.py) receives
    the same container this fixture started.

    TODO: Migrate all remaining get_instance() callers to accept this fixture as a parameter,
          then switch back to direct instantiation: Neo4jTemporaryInstance(max_retry_seconds=240)
    """
    instance = Neo4jTemporaryInstance.get_instance(max_retry_seconds=240)
    yield instance
    instance.shutdown()
