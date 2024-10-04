import logging
from collections.abc import Sequence

import redis

from eduid.userdb.testing import EduidTemporaryInstance

logger = logging.getLogger(__name__)


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
        return self._conn

    def get_params(self) -> tuple[str, int, int]:
        """
        Convenience function to get Redis connection parameters for the temporary database.

        :return: Host, port and database
        """
        return "localhost", self.port, 0
