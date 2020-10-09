# -*- coding: utf-8 -*-

import logging
import logging.config
import time
from os import environ
from pprint import PrettyPrinter
from typing import Optional

logger = logging.getLogger(__name__)

__author__ = 'lundberg'

"""
Adds the following entries to logging context:
system_hostname - Set with environment variable SYSTEM_HOSTNAME
app_name - app name
"""

DEFAULT_FORMAT = '%(asctime)s | %(levelname)s | %(hostname)s | %(name)s | %(module)s | %(message)s'


# Default to RFC3339/ISO 8601 with tz
class EduidFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        if datefmt:
            s = time.strftime(datefmt, ct)
        else:
            t = time.strftime('%Y-%m-%dT%H:%M:%S', ct)
            tz = time.strftime('%z', ct)  # Can evaluate to empty string
            if tz:
                tz = '{0}:{1}'.format(tz[:3], tz[3:])  # Need colon to follow the rfc/iso
            s = '{}.{:03.0f}{}'.format(t, record.msecs, tz)
        return s


class AppFilter(logging.Filter):
    def __init__(self, app_name):
        logging.Filter.__init__(self)
        self.app_name = app_name

    def filter(self, record):
        record.system_hostname = environ.get('SYSTEM_HOSTNAME', '')  # Underlying hosts name for containers
        record.hostname = environ.get('HOSTNAME', '')  # Actual hostname or container id
        record.app_name = self.app_name
        return True


class RequireDebugTrue(logging.Filter):
    def __init__(self, app_debug):
        logging.Filter.__init__(self)
        self.app_debug = app_debug

    def filter(self, record):
        return self.app_debug


class RequireDebugFalse(logging.Filter):
    def __init__(self, app_debug):
        logging.Filter.__init__(self)
        self.app_debug = app_debug

    def filter(self, record):
        return not self.app_debug


def merge_config(base_config: dict, new_config: dict) -> dict:
    def merge(node, key, value):
        if isinstance(value, dict):
            for item in value:
                try:
                    merge(node[key], item, value[item])
                except KeyError:
                    # No such key in base_config, just set it
                    node[key] = value
        else:
            node[key] = value

    for k, v in new_config.items():
        merge(base_config, k, v)
    return base_config


def init_logging(app_name: str, config: Optional[dict] = None) -> None:
    """
    Init logging using dictConfig.

    Will look for the following settings keys:
    LOG_LEVEL
    LOG_FORMAT (optional)
    DEBUG (default False)

    Merges optional dictConfig from settings before initializing.
    """

    local_context = {
        'level': environ.get('LOG_LEVEL', 'INFO'),
        'format': environ.get('LOG_FORMAT', DEFAULT_FORMAT),
        'app_name': app_name,
        'app_debug': bool(environ.get('DEBUG', False)),
    }

    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        # Local variables
        'local_context': local_context,
        'formatters': {
            'default': {'()': 'eduid_queue.log.EduidFormatter', 'fmt': 'cfg://local_context.format'},
        },
        'filters': {
            'app_filter': {'()': 'eduid_queue.log.AppFilter', 'app_name': 'cfg://local_context.app_name'},
            'require_debug_true': {
                '()': 'eduid_queue.log.RequireDebugTrue',
                'app_debug': 'cfg://local_context.app_debug',
            },
            'require_debug_false': {
                '()': 'eduid_queue.log.RequireDebugFalse',
                'app_debug': 'cfg://local_context.app_debug',
            },
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'cfg://local_context.level',
                'formatter': 'default',
                'filters': ['app_filter'],
            },
        },
        'root': {'handlers': ['console'], 'level': 'cfg://local_context.level'},
    }
    if config is not None:
        logging_config = merge_config(logging_config, config)
    logging.config.dictConfig(logging_config)
    if local_context.get('debug'):
        pp = PrettyPrinter()
        logger.debug(f'Logging config:\n{pp.pformat(logging_config)}')
    logger.info('Logging configured')
    return None
