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


class AppStats(ABC):

    @abstractmethod
    def count(self, name, value=1):
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

    def count(self, name, value=1):
        if self.logger:
            if self.prefix:
                name = '{!s}.{!s}'.format(self.prefix, name)
            self.logger.info('No-op stats count: {!r} {!r}'.format(name, value))


class Statsd(AppStats):
    def __init__(self, host, port, prefix=None):
        import statsd

        self.client = statsd.StatsClient(host, port, prefix=prefix)

    def count(self, name, value=1):
        self.client.incr('{}.average'.format(name), count=value)
        # You need to set up a storage aggregation that uses sum instead of the default average
        # for .count
        self.client.incr('{}.count'.format(name), count=value)


# importing EduIDBaseApp in this module leads to a circular import
def init_app_stats(app: 'EduIDBaseApp') -> AppStats:
    _stats: AppStats
    stats_host = app.config.stats_host
    if not stats_host:
        _stats = NoOpStats()
    else:
        stats_port = app.config.stats_port
        _stats = Statsd(host=stats_host, port=stats_port, prefix=app.name)
    return _stats
