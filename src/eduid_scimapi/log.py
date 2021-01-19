# -*- coding: utf-8 -*-
from logging.config import dictConfig

from eduid_common.api.logging import LocalContext, LoggingFilters, make_dictConfig
from eduid_common.config.exceptions import BadConfiguration


__author__ = 'lundberg'

from eduid_scimapi.config import ScimApiConfig

DEFAULT_FORMAT = '{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}'


def make_local_context(app_name: str, config: ScimApiConfig) -> LocalContext:
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
            app_name=app_name,
            app_debug=config.debug,
            debug_eppns=config.debug_eppns,
            filters=filters,
            relative_time=relative_time,
        )
    except (KeyError, AttributeError) as e:
        raise BadConfiguration(message=f'Could not initialize logging local_context. {type(e).__name__}: {e}')
    return local_context


def init_logging(app_name: str, config: ScimApiConfig) -> None:
    local_context = make_local_context(app_name, config)
    logging_config = make_dictConfig(local_context)
    dictConfig(logging_config)
    return None
