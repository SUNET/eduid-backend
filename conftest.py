from __future__ import annotations

from collections.abc import Iterator

import pytest

from eduid.graphdb.testing import Neo4jTemporaryInstance
from eduid.queue.testing import MongoTemporaryInstanceReplicaSet, SMPTDFixTemporaryInstance
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

    TODO: Migrate all remaining get_instance() callers to accept this fixture as a parameter,
          then switch back to direct instantiation: RedisTemporaryInstance(max_retry_seconds=60)
    """
    instance = RedisTemporaryInstance.get_instance(max_retry_seconds=60)
    yield instance
    instance.shutdown()


@pytest.fixture(scope="session")
def neo4j_instance(
    mongo_instance: MongoTemporaryInstance,
    redis_instance: RedisTemporaryInstance,
) -> Iterator[Neo4jTemporaryInstance]:
    """One Neo4j container per test session.

    Neo4j test files are marked with xdist_group('neo4j') so all Neo4j tests
    run on a single worker — only one container ever starts.

    Depends on mongo_instance and redis_instance so that those lightweight containers
    start first. Without this, the neo4j worker would start Neo4j first (slow, up to 240s)
    and then Redis/MongoDB would have no time budget left.

    Uses get_instance() so that legacy code still calling Neo4jTemporaryInstance.get_instance()
    directly (outside of fixture injection, e.g. from update_config() in test_app.py) receives
    the same container this fixture started.

    TODO: Migrate all remaining get_instance() callers to accept this fixture as a parameter,
          then switch back to direct instantiation: Neo4jTemporaryInstance(max_retry_seconds=240)
    """
    instance = Neo4jTemporaryInstance.get_instance(max_retry_seconds=240)
    yield instance
    instance.shutdown()


@pytest.fixture(scope="session")
def mongo_replica_set_instance() -> Iterator[MongoTemporaryInstanceReplicaSet]:
    """One MongoDB replica-set container per test session (i.e. per pytest-xdist worker).

    Used by queue tests. Uses get_instance() so that EduidQueueTestCase.setup_queue,
    which calls MongoTemporaryInstanceReplicaSet.get_instance() directly, gets the same
    container this fixture started — and teardown is handled here, not by atexit.

    TODO: Migrate setup_queue to accept this fixture as a parameter, then switch back
          to direct instantiation: MongoTemporaryInstanceReplicaSet(max_retry_seconds=60)
    """
    instance = MongoTemporaryInstanceReplicaSet.get_instance(max_retry_seconds=60)
    yield instance
    instance.shutdown()


@pytest.fixture(scope="session")
def smtpdfix_instance() -> Iterator[SMPTDFixTemporaryInstance]:
    """One SMTPDFix container per test session (i.e. per pytest-xdist worker)."""
    instance = SMPTDFixTemporaryInstance(max_retry_seconds=60)
    yield instance
    instance.shutdown()
