"""
Statistics gathering.

An instance of either NoOpStats() or Statsd() is made available through the
request object, so that statistics information can be logged without any checks
for configured object or not.

Example usage in some view:

    request.stats.count('verify_code_completed')

"""

__author__ = "ft"

import re
import socket
from abc import ABC, abstractmethod
from logging import Logger

from eduid.common.config.base import StatsConfigMixin


class AppStats(ABC):
    @abstractmethod
    def count(self, name: str, value: int = 1) -> None:
        pass

    @abstractmethod
    def gauge(self, name: str, value: int, rate: int = 1, delta: bool = False) -> None:
        pass

    @staticmethod
    def clean_name(name: str) -> str:
        """
        Remove any char that are not allowed in statsd parsing.
        Sanitize a name string by:
         - Replacing whitespace with '_'
         - Replacing '/' with '-'
         - Removing characters not matching 'a-zA-Z_\\-0-9\\.;='
        """
        # Replace whitespace with underscore
        result = "_".join(name.split())

        # Replace '/' with '-'
        result = result.replace("/", "-")

        # Remove characters not matching the allowed pattern
        result = re.sub(r"[^a-zA-Z_\-0-9.;=]", "", result)
        return result


class NoOpStats(AppStats):
    """
    No-op class used when statsd server is not set.

    Having this no-op class initialized in case there is no statsd_server
    configured allows us to not check if current_app.stats is set everywhere.
    """

    def __init__(self, logger: Logger | None = None, prefix: str | None = None) -> None:
        self.logger = logger
        self.prefix = prefix

    def count(self, name: str, value: int = 1) -> None:
        name = self.clean_name(name)
        if self.logger:
            if self.prefix:
                name = f"{self.prefix!s}.{name!s}"
            self.logger.info(f"No-op stats count: {name!r} {value!r}")

    def gauge(self, name: str, value: int, rate: int = 1, delta: bool = False) -> None:
        name = self.clean_name(name)
        if self.logger:
            if self.prefix:
                name = f"{self.prefix!s}.{name!s}"
            self.logger.info(f"No-op stats gauge: {name} {value}")


class Statsd(AppStats):
    def __init__(self, host: str, port: int, prefix: str | None = None) -> None:
        import statsd

        class _LazyStatsClient(statsd.StatsClient):
            """
            statsd.StatsClient resolves the host with getaddrinfo() in __init__ and caches
            the address forever. Under docker compose the stats service name is resolved via
            docker's embedded DNS, which is not guaranteed to be resolvable when a gunicorn
            worker boots (boot race) and whose IP changes when the stats container restarts.

            This subclass defers resolution to the first send and re-resolves after any send
            failure, so startup never crashes on a transient DNS error and a restarted stats
            container (new IP) is picked up automatically. UDP sends already fail silently.
            """

            def __init__(self, host: str, port: int, prefix: str | None) -> None:
                self._host = host
                self._port = port
                self._addr: tuple | None = None
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._prefix = prefix
                self._maxudpsize = 512

            def _resolve(self) -> None:
                _, _, _, _, self._addr = socket.getaddrinfo(self._host, self._port, socket.AF_INET, socket.SOCK_DGRAM)[
                    0
                ]

            def _send(self, data: str) -> None:
                try:
                    if self._addr is None:
                        self._resolve()
                    assert self._addr is not None  # narrow for mypy; _resolve() always sets it
                    self._sock.sendto(data.encode("ascii"), self._addr)
                except OSError:
                    # force re-resolution on next send (handles restart / new IP / late DNS)
                    self._addr = None

        self.client = _LazyStatsClient(host, port, prefix)

    def count(self, name: str, value: int = 1) -> None:
        name = self.clean_name(name)
        self.client.incr(f"{name}.average", count=value)
        # You need to set up a storage aggregation that uses sum instead of the default average
        # for .count
        self.client.incr(f"{name}.count", count=value)

    def gauge(self, name: str, value: int, rate: int = 1, delta: bool = False) -> None:
        name = self.clean_name(name)
        self.client.gauge(f"{name}.gauge", value=value, rate=rate, delta=delta)


def init_app_stats(config: StatsConfigMixin) -> AppStats:
    _stats: AppStats
    if not config.stats_host:
        _stats = NoOpStats()
    else:
        stats_port = config.stats_port
        _stats = Statsd(host=config.stats_host, port=stats_port, prefix=config.app_name)
    return _stats
