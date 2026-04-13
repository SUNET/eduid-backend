from __future__ import annotations

import logging
import random
import shutil
import socket
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

from eduid.common.misc.timeutil import utc_now

logger = logging.getLogger(__name__)


def get_available_port(min_port: int = 40000, max_port: int = 65535, exclude: set[int] | None = None) -> int:
    if min_port > max_port:
        raise ValueError("min_port must be less than or equal to max_port")
    excluded_ports = exclude or set()
    for _ in range(100):
        port = random.randint(min_port, max_port)
        if port in excluded_ports:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    raise RuntimeError(f"Failed to find a free port in range {min_port}-{max_port}")


class EduidTemporaryInstance(ABC):
    """Manage a temporary instance of something needed when testing."""

    def __init__(self, max_retry_seconds: int) -> None:
        self._conn: Any | None = None  # self._conn should be initialised by subclasses in `setup_conn'
        self._tmpdir = tempfile.mkdtemp()
        self._port = get_available_port()
        self._logfile = open(f"/tmp/{self.__class__.__name__}-{self.port}.log", "w")  # noqa: SIM115

        start_time = utc_now()
        self._process = subprocess.Popen(self.command, stdout=self._logfile, stderr=subprocess.STDOUT)

        interval = 0.2
        count = 0
        while True:
            count += 1
            time.sleep(interval)

            # Call a function of the subclass of this ABC to see if the instance is operational yet
            _res = self.setup_conn()

            time_now = utc_now()
            delta = time_now - start_time
            age = delta.total_seconds()
            if _res:
                logger.info(f"{self} instance started after {age} seconds (attempt {count})")
                break
            if age > max_retry_seconds:
                logger.error(f"{self} instance on port {self.port} failed to start after {age} seconds")
                logger.error(f"{self} instance output:\n{self.output}")
                self.shutdown()
                raise RuntimeError(f"{self} instance on port {self.port} failed to start after {age} seconds")
            if count <= 3:  # noqa: PLR2004
                # back off slightly
                interval += interval

    @abstractmethod
    def setup_conn(self) -> bool:
        """
        Initialise and test a connection of the instance in self._conn.

        Return True on success.
        """
        raise NotImplementedError("All subclasses of EduidTemporaryInstance must implement setup_conn")

    @property
    @abstractmethod
    def conn(self) -> Any:  # noqa: ANN401
        """Return the initialised _conn instance. No default since it ought to be typed in the subclasses."""
        raise NotImplementedError("All subclasses of EduidTemporaryInstance should implement the conn property")

    @property
    @abstractmethod
    def command(self) -> Sequence[str]:
        """This is the shell command to start the temporary instance."""
        raise NotImplementedError("All subclasses of EduidTemporaryInstance must implement the command property")

    @property
    def port(self) -> int:
        return self._port

    @property
    def tmpdir(self) -> str:
        return self._tmpdir

    @property
    def output(self) -> str:
        with open(self._logfile.name) as fd:
            _output = "".join(fd.readlines())
        return _output

    def shutdown(self) -> None:
        if getattr(self, "_shutdown_done", False):
            return  # atexit and fixture teardown both call shutdown(); only run once
        self._shutdown_done = True
        logger.debug(f"{self} shutting down (log at {self._logfile.name})")
        if self._process:
            # Get container name from command
            container_name = None
            for arg in self.command:
                if arg.startswith("test_"):
                    container_name = arg
                    break

            if container_name:
                # Non-blocking: docker kill is slow in this environment so we do not wait.
                # The child will be reaped by init when pytest exits (not by us), leaving
                # a brief zombie entry — acceptable since only one container runs per session.
                subprocess.Popen(
                    ["docker", "kill", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                self._process.terminate()

        if hasattr(self, "_logfile") and self._logfile and not self._logfile.closed:
            self._logfile.flush()

        if "tmp" in self._tmpdir:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
