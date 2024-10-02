from collections.abc import Mapping
from pathlib import Path
from typing import Any

from eduid.common.config.parsers import BaseConfigParser
from eduid.common.config.parsers.decorators import decrypt, interpolate


class YamlConfigParser(BaseConfigParser):
    def __init__(self, path: Path) -> None:
        self.path = path

    @interpolate
    @decrypt
    def read_configuration(self, path: str) -> Mapping[str, Any]:
        with self.path.open() as fd:
            import yaml

            data = yaml.safe_load(fd)

        # traverse the loaded data to the right namespace, discarding everything else
        for this in path.split("/"):
            if not this:
                continue
            data = data[this]

        # lowercase all keys
        lc_data = {k.lower(): v for k, v in data.items()}

        return lc_data
