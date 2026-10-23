import logging
from collections.abc import Callable, Generator, Sequence
from contextlib import contextmanager
from typing import cast

import redis
from flask import request
from pytest_mock import MockerFixture

from eduid.userdb.testing.temp_instance import EduidTemporaryInstance
from eduid.webapp.common.session.redis_session import RedisEncryptedSession

logger = logging.getLogger(__name__)


class SessionConflictForcer:
    """Reports whether a concurrent session commit has been forced (see force_session_conflict_on_post)"""

    def __init__(self) -> None:
        self.forced = False


@contextmanager
def force_session_conflict_on_post(
    mocker: MockerFixture, sibling_action: Callable[[RedisEncryptedSession], None] | None = None
) -> Generator[SessionConflictForcer]:
    """
    Make the first POST request made inside the context lose its session commit.

    Right before the request's session is persisted, a sibling writer commits a change to the same
    backend session, so that the request's own commit raises SessionOutOfSync (or is swallowed,
    depending on what the request changed).

    :param mocker: pytest-mock fixture
    :param sibling_action: What the sibling writer does, default is adding a harmless key. It is
        responsible for committing, e.g. a logout is `lambda s: s.clear()`.
    """
    from eduid.webapp.common.session.eduid_session import EduidSession, SessionFactory

    forcer = SessionConflictForcer()
    real_persist = EduidSession.persist

    def racing_persist(this: EduidSession) -> None:
        if request.method == "POST" and not forcer.forced:
            forcer.forced = True
            factory = this.app.session_interface
            assert isinstance(factory, SessionFactory)
            sibling = factory.manager.get_session(meta=this.meta, new=False)
            if sibling_action is None:
                sibling["sibling"] = "writer"
                sibling.commit()
            else:
                sibling_action(sibling)
        real_persist(this)

    patched = mocker.patch.object(EduidSession, "persist", autospec=True, side_effect=racing_persist)
    try:
        yield forcer
    finally:
        mocker.stop(patched)


class RedisTemporaryInstance(EduidTemporaryInstance):
    """Singleton to manage a temporary Redis instance

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.

    """

    @property
    def command(self) -> Sequence[str]:
        return [
            "docker",
            "run",
            "--rm",
            "-p",
            f"{self.port!s}:6379",
            "--name",
            f"test_redis_{self.port}",
            "-v",
            f"{self.tmpdir}:/data",
            "-e",
            "extra_args=--daemonize no --bind 0.0.0.0",
            "docker.sunet.se/eduid/redis:latest",
        ]

    def setup_conn(self) -> bool:
        try:
            host, port, db = self.get_params()
            _conn = redis.Redis(host, port, db)
            _conn.set("dummy", "dummy")
            self._conn = _conn
        except redis.exceptions.ConnectionError:
            return False
        return True

    @property
    def conn(self) -> redis.Redis:
        if self._conn is None:
            raise RuntimeError("Missing temporary Redis instance")
        return cast(redis.Redis, self._conn)

    def get_params(self) -> tuple[str, int, int]:
        """
        Convenience function to get Redis connection parameters for the temporary database.

        :return: Host, port and database
        """
        return "localhost", self.port, 0
