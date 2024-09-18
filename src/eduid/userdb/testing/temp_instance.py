from __future__ import annotations

import atexit
import logging
import random
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

from eduid.userdb.util import utc_now

logger = logging.getLogger(__name__)


class EduidTemporaryInstance(ABC):
    """Singleton to manage a temporary instance of something needed when testing.

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.
    """

    _instance = None

    def __init__(self, max_retry_seconds: int):
        self._conn: Any | None = None  # self._conn should be initialised by subclasses in `setup_conn'
        self._tmpdir = tempfile.mkdtemp()
        self._port = random.randint(40000, 65535)
        self._logfile = open(f"/tmp/{self.__class__.__name__}-{self.port}.log", "w")

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
            if count <= 3:
                # back off slightly
                interval += interval

    @classmethod
    def get_instance(cls: type[EduidTemporaryInstance], max_retry_seconds: int = 60) -> EduidTemporaryInstance:
        """
        Start a new temporary instance, or retrieve an already started one.

        :param max_retry_seconds: Time allowed for the instance to start
        :return:
        """
        if cls._instance is None:
            cls._instance = cls(max_retry_seconds=max_retry_seconds)
            atexit.register(cls._instance.shutdown)
        return cls._instance

    @abstractmethod
    def setup_conn(self) -> bool:
        """
        Initialise and test a connection of the instance in self._conn.

        Return True on success.
        """
        raise NotImplementedError("All subclasses of EduidTemporaryInstance must implement setup_conn")

    @property
    @abstractmethod
    def conn(self) -> Any:
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

    def shutdown(self):
        logger.debug(f"{self} output at shutdown:\n{self.output}")
        if self._process:
            self._process.terminate()
            self._process.wait()
        self._logfile.close()
        if "tmp" in self._tmpdir:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
