# -*- coding: utf-8 -*-

from __future__ import annotations

import logging
import logging.config
import time
from dataclasses import asdict, dataclass, field
from enum import Enum, unique
from os import environ
from pprint import pformat
from typing import TYPE_CHECKING, Any, Dict, List, Sequence

from eduid_common.config.exceptions import BadConfiguration

try:
    # Do not fail if Flask is missing, we want to use this in other projects
    from eduid_common.session import session
except ImportError:
    session = None  # type: ignore

# From https://stackoverflow.com/a/39757388
# The TYPE_CHECKING constant is always False at runtime, so the import won't be evaluated, but mypy
# (and other type-checking tools) will evaluate the contents of that block.
if TYPE_CHECKING:
    from eduid_common.api.app import EduIDBaseApp


__author__ = 'lundberg'

"""
Adds the following entries to logging context:
system_hostname - Set with environment variable SYSTEM_HOSTNAME
app_name - Flask app name
eppn - Available if a user session is initiated
"""

DEFAULT_FORMAT = '{asctime} | {levelname:7} | {hostname} | {eppn:11} | {name:35} | {module:10} | {message}'


# Default to RFC3339/ISO 8601 with tz
class EduidFormatter(logging.Formatter):
    def __init__(self, relative_time: bool = False, fmt=None):
        super().__init__(fmt=fmt, style='{')
        self._relative_time = relative_time

    def formatTime(self, record: logging.LogRecord, datefmt=None) -> str:
        if self._relative_time:
            # Relative time makes much more sense than absolute time when running tests for example
            _seconds = record.relativeCreated / 1000
            return f'{_seconds:.3f}s'

        # self.converter seems incorrectly typed as a two-argument method (Callable[[Optional[float]], struct_time])
        ct = self.converter(record.created)  # type: ignore
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
    """ Add `system_hostname`, `hostname` and `app_name` to records being logged. """

    def __init__(self, app_name):
        super().__init__()
        self.app_name = app_name
        # TODO: I guess it could be argued that these should be put in the LocalContext and not evaluated at runtime.
        self.hostname = environ.get('HOSTNAME', '')
        self.system_hostname = environ.get('SYSTEM_HOSTNAME', '')

    def filter(self, record: logging.LogRecord) -> bool:
        # use setattr to prevent mypy unhappiness
        record.__setattr__('app_name', self.app_name)
        record.__setattr__('hostname', self.hostname)  # Actual hostname or container id
        record.__setattr__('system_hostname', self.system_hostname)  # Underlying hosts name for containers
        return True


class UserFilter(logging.Filter):
    """
    A filter to add eppn to the log records.

    Additionally, if debug_eppns is set, only allow debug log entries where the eppn is found in debug_eppns.
    This allows us to debug-log certain users in production, without having debug logging enabled for everyone.
    """

    def __init__(self, debug_eppns: Sequence[str]):
        super().__init__()
        self.debug_eppns = debug_eppns

    def filter(self, record: logging.LogRecord) -> bool:
        eppn = ''
        if session:
            eppn = session.get('user_eppn', '')
        record.__setattr__('eppn', eppn)  # use setattr to prevent mypy unhappiness
        if record.levelno == logging.DEBUG:
            # If debug_eppns is not empty, we filter debug messages here and only allow them
            # (return True) if the eppn found in the session above is present in the debug_eppns list.
            if self.debug_eppns and eppn not in self.debug_eppns:
                # debug_eppns is not empty, but the eppn is not present in it
                return False
        return True


class RequireDebugTrue(logging.Filter):
    """ A filter to discard all debug log records if the Flask app.debug is not True. Generally not used. """

    def __init__(self, app_debug: bool):
        super().__init__()
        self.app_debug = app_debug

    def filter(self, record: logging.LogRecord) -> bool:
        return self.app_debug


class RequireDebugFalse(logging.Filter):
    """ A filter to discard all debug log records if the Flask app.debug is not False. Generally not used. """

    def __init__(self, app_debug: bool):
        super().__init__()
        self.app_debug = app_debug

    def filter(self, record: logging.LogRecord) -> bool:
        return not self.app_debug


def merge_config(base_config: Dict[str, Any], new_config: Dict[str, Any]) -> Dict[str, Any]:
    """ Recursively merge two dictConfig dicts. """

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


def init_logging(app: EduIDBaseApp) -> None:
    """
    Init logging in a Flask app using dictConfig.

    See `make_local_context` for how to configure logging.

    Merges optional dictConfig from settings before initializing (config key 'logging_config').
    """
    local_context = make_local_context(app)
    logging_config = make_dictConfig(local_context)

    logging_config = merge_config(logging_config, app.config.logging_config)

    logging.config.dictConfig(logging_config)
    if app.debug:
        app.logger.debug(f'Logging config:\n{pformat(logging_config)}')
    app.logger.info('Logging configured')
    return None


@unique
class LoggingFilters(Enum):
    """ Identifiers to coherently map elements in LocalContext.filters to filter classes. """

    DEBUG_TRUE: str = 'require_debug_true'
    DEBUG_FALSE: str = 'require_debug_false'
    NAMES: str = 'app_filter'
    SESSION_USER: str = 'user_filter'


@dataclass
class LocalContext:
    level: str  # 'DEBUG', 'INFO' etc.
    format: str  # logging format string (using style '{')
    app_name: str  # the name of the application
    app_debug: bool  # Is the app in debug mode? Corresponding to current_app.debug
    # optionally filter debug messages to only be emitted if eppn is in this list
    debug_eppns: Sequence[str] = field(default_factory=list)
    filters: List[LoggingFilters] = field(default_factory=list)  # filters to activate
    relative_time: bool = False  # use relative time as {asctime}

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res['level'] = logging.getLevelName(self.level)
        return res


def make_local_context(app: EduIDBaseApp) -> LocalContext:
    """
    Local context is a place to put parameters for filters and formatters in logging dictConfigs.

    To provide typing and order, we keep them in a neat dataclass.
    """
    log_format = app.config.log_format
    if not log_format:
        log_format = DEFAULT_FORMAT

    log_level = app.config.log_level
    if app.debug:
        # Flask expects to be able to debug log in debug mode
        log_level = 'DEBUG'

    filters = [LoggingFilters.NAMES, LoggingFilters.SESSION_USER]

    relative_time = app.config.testing

    try:
        local_context = LocalContext(
            level=log_level,
            format=log_format,
            app_name=app.name,
            app_debug=app.debug,
            debug_eppns=app.config.debug_eppns,
            filters=filters,
            relative_time=relative_time,
        )
    except (KeyError, AttributeError) as e:
        raise BadConfiguration(message=f'Could not initialize logging local_context. {type(e).__name__}: {e}')
    return local_context


def make_dictConfig(local_context: LocalContext) -> Dict[str, Any]:
    """
    Create configuration for logging.dictConfig.

    Anything that needs to be parameterised should be put in LocalContext, which is
    a place to put arguments to various filters/formatters as well as anything else we
    need.
    """

    _available_filters = {
        # A filter that adds various hostname/container name information to the log records
        LoggingFilters.NAMES: {'()': 'eduid_common.api.logging.AppFilter', 'app_name': 'cfg://local_context.app_name',},
        # Only log debug messages if Flask app.debug is False
        LoggingFilters.DEBUG_FALSE: {
            '()': 'eduid_common.api.logging.RequireDebugFalse',
            'app_debug': 'cfg://local_context.app_debug',
        },
        # Only log debug messages if Flask app.debug is True
        LoggingFilters.DEBUG_TRUE: {
            '()': 'eduid_common.api.logging.RequireDebugTrue',
            'app_debug': 'cfg://local_context.app_debug',
        },
        # A filter that adds relative time to the log records
        LoggingFilters.SESSION_USER: {
            '()': 'eduid_common.api.logging.UserFilter',
            'debug_eppns': 'cfg://local_context.debug_eppns',
        },
    }

    # Choose filters. Technically, they could all be included always,
    # since they have to appear in the 'filters' list of a handler in order to
    # be invoked, but we only include the requested ones for tidiness and readability.
    filters = {k: v for k, v in _available_filters.items() if k in local_context.filters}

    base_config = {
        'version': 1,
        'disable_existing_loggers': False,
        # Local variables
        'local_context': local_context.to_dict(),
        # Formatters
        'formatters': {
            'default': {
                '()': 'eduid_common.api.logging.EduidFormatter',
                'relative_time': 'cfg://local_context.relative_time',
                'fmt': 'cfg://local_context.format',
            },
        },
        # Filters
        'filters': filters,
        # Handlers
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'cfg://local_context.level',
                'formatter': 'default',
                'filters': local_context.filters,
            },
        },
        # Loggers
        'root': {'handlers': ['console'], 'level': 'cfg://local_context.level',},
    }
    return base_config
