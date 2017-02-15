"""
Statistics gathering.

An instance of either NoOpStats() or Statsd() is made available through the
request object, so that statistics information can be logged without any checks
for configured object or not.

Example usage in some view:

    request.stats.count('verify_code_completed')

"""

__author__ = 'ft'


class NoOpStats(object):
    """
    No-op class used when stathats_user is not set.

    Having this no-op class initialized in case there is no statsd_server
    configured allows us to not check if request.stats is set everywhere.
    """
    def __init__(self, logger = None, prefix=None):
        self.logger = logger
        self.prefix = None

    def count(self, name, value):
        if self.logger:
            if self.prefix:
                name = '{!s}.{!s}'.format(self.prefix, name)
            self.logger.info('No-op stats count: {!r} {!r}'.format(name, value))


class Statsd(object):

    def __init__(self, host, port, prefix=None):
        import statsd
        self.client = statsd.StatsClient(host, port, prefix=prefix)

    def count(self, name, value=1):
        self.client.incr(name, count=value)

