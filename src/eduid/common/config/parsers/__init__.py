import json
import os
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Type

import yaml

from eduid.common.config.base import FlaskConfig, TRootConfigSubclass

__author__ = "ft"

from eduid.common.config.parsers.base import BaseConfigParser
from eduid.common.config.parsers.exceptions import ParserException


def load_config(
    typ: Type[TRootConfigSubclass],
    ns: str,
    app_name: str,
    test_config: Optional[Mapping[str, Any]] = None,
) -> TRootConfigSubclass:
    """Figure out where to load configuration from, and do it."""
    app_path = os.environ.get("EDUID_CONFIG_NS", f"/eduid/{ns}/{app_name}/")
    common_path = os.environ.get("EDUID_CONFIG_COMMON_NS", f"/eduid/{ns}/common/")

    parser = _choose_parser()

    if not parser:
        raise ParserException("Could not find a suitable config parser")

    config: Dict[str, Any]

    if test_config:
        config = dict(test_config)
    else:
        common_config = parser.read_configuration(common_path)
        app_config = parser.read_configuration(app_path)

        config = dict(common_config)
        config.update(app_config)

    if "secret_key" in config:
        # Looks like there could be a FlaskConfig mixed into the config
        config["flask"] = FlaskConfig(**config)

    if "celery_config" in config and not "celery" in config:
        config["celery"] = config["celery_config"]

    if "app_name" not in config:
        config["app_name"] = app_name

    res = typ(**config)

    # Save config to a file in /dev/shm for introspection
    fd_int = os.open(f"/dev/shm/{app_name}_config.yaml", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(fd_int, "w") as fd:
        fd.write("---\n")
        # have to take the detour over json to get things like enums serialised to strings
        yaml.safe_dump(json.loads(res.json()), fd)

    return res


def _choose_parser() -> Optional[BaseConfigParser]:
    """
    Choose a parser to use for this app.

    Do local imports accordingly to not make yaml etc. mandatory requirements for
    all users of eduid.common.

    :return: Config parser instance
    """
    parser: Optional[BaseConfigParser] = None
    yaml_file = os.environ.get("EDUID_CONFIG_YAML")
    if yaml_file:
        try:
            from eduid.common.config.parsers.yaml_parser import YamlConfigParser

            parser = YamlConfigParser(path=Path(yaml_file))
        except ImportError:
            raise ParserException("YamlConfigParser could not be imported")
    return parser
