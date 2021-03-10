# -*- coding: utf-8 -*-
from logging.config import dictConfig

from eduid.common.api.logging import LocalContext, LoggingFilters, make_dictConfig
from eduid.common.config.exceptions import BadConfiguration
from eduid.queue.config import QueueWorkerConfig

__author__ = 'lundberg'

DEFAULT_FORMAT = '{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}'


def make_local_context(config: QueueWorkerConfig) -> LocalContext:
    """
    Local context is a place to put parameters for filters and formatters in logging dictConfigs.

    To provide typing and order, we keep them in a neat dataclass.
    """
    log_format = config.log_format
    if not log_format:
        log_format = DEFAULT_FORMAT

    log_level = config.log_level
    if config.debug:
        # Flask expects to be able to debug log in debug mode
        log_level = 'DEBUG'

    filters = [LoggingFilters.NAMES]

    relative_time = config.testing

    try:
        local_context = LocalContext(
            level=log_level,
            format=log_format,
            app_name=config.app_name,
            app_debug=config.debug,
            debug_eppns=config.debug_eppns,
            filters=filters,
            relative_time=relative_time,
        )
    except (KeyError, AttributeError) as e:
        raise BadConfiguration(message=f'Could not initialize logging local_context. {type(e).__name__}: {e}')
    return local_context


def init_logging(config: QueueWorkerConfig) -> None:
    local_context = make_local_context(config)
    logging_config = make_dictConfig(local_context)
    dictConfig(logging_config)
    return None
