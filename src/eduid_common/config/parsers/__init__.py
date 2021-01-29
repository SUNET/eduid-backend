# -*- coding: utf-8 -*-
import os
from pathlib import Path
from typing import Any, Mapping, Optional, Type

from eduid_common.config.base import TRootConfigSubclass
from eduid_common.config.parsers.base import BaseConfigParser

__author__ = 'ft'

from eduid_common.config.parsers.exceptions import ParserException


def load_config(
    typ: Type[TRootConfigSubclass], ns: str, app_name: str, test_config: Optional[Mapping[str, Any]] = None,
) -> TRootConfigSubclass:
    """ Figure out where to load configuration from, and do it. """
    parser = _choose_parser(app_name, ns)

    if not parser:
        raise ParserException('Could not find a suitable config parser')

    if test_config:
        return typ(**test_config)

    config = parser.read_configuration()

    return typ(**config)


def _choose_parser(app_name: str, ns: str) -> Optional[BaseConfigParser]:
    """
    Choose a parser to use for this app.

    Do local imports accordingly to not make etcd, yaml etc. mandatory requirements for
    all users of eduid-common.

    :param app_name: Name of the application
    :param ns: Namespace for the application

    :return: Config parser instance
    """
    parser: Optional[BaseConfigParser] = None
    ns = os.environ.get('EDUID_CONFIG_NS', ns)
    app_name = os.environ.get('EDUID_CONFIG_APP_NAME', app_name)
    yaml_file = os.environ.get('EDUID_CONFIG_YAML')
    if yaml_file:
        try:
            from eduid_common.config.parsers.yaml import YamlConfigParser

            parser = YamlConfigParser(path=Path(yaml_file), ns=ns, app_name=app_name)
        except ImportError:
            raise ParserException('YamlConfigParser could not be imported')
    if not parser:
        try:
            from eduid_common.config.parsers.etcd import EtcdConfigParser
        except ImportError:
            raise ParserException('EtcdConfigParser could not be imported')

        parser = EtcdConfigParser(namespace=ns)
    return parser
