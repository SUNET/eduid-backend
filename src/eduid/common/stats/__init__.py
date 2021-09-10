"""
Statistics gathering.

An instance of either NoOpStats() or Statsd() is made available through the
request object, so that statistics information can be logged without any checks
for configured object or not.

Example usage in some view:

    request.stats.count('verify_code_completed')

"""

__author__ = 'ft'

from abc import ABC, abstractmethod

from eduid.common.config.base import StatsConfigMixin


class AppStats(ABC):
    @abstractmethod
    def count(self, name: str, value: int = 1) -> None:
        pass


class NoOpStats(AppStats):
    """
    No-op class used when statsd server is not set.

    Having this no-op class initialized in case there is no statsd_server
    configured allows us to not check if current_app.stats is set everywhere.
    """

    def __init__(self, logger=None, prefix=None):
        self.logger = logger
        self.prefix = prefix

    def count(self, name: str, value: int = 1) -> None:
        if self.logger:
            if self.prefix:
                name = '{!s}.{!s}'.format(self.prefix, name)
            self.logger.info('No-op stats count: {!r} {!r}'.format(name, value))


class Statsd(AppStats):
    def __init__(self, host, port, prefix=None):
        import statsd

        self.client = statsd.StatsClient(host, port, prefix=prefix)

    def count(self, name: str, value: int = 1) -> None:
        self.client.incr('{}.average'.format(name), count=value)
        # You need to set up a storage aggregation that uses sum instead of the default average
        # for .count
        self.client.incr('{}.count'.format(name), count=value)


def init_app_stats(config: StatsConfigMixin) -> AppStats:
    _stats: AppStats
    if not config.stats_host:
        _stats = NoOpStats()
    else:
        stats_port = config.stats_port
        _stats = Statsd(host=config.stats_host, port=stats_port, prefix=config.app_name)
    return _stats
