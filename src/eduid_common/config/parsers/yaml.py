from pathlib import Path
from typing import Any, Dict, Mapping

from eduid_common.config.parsers import BaseConfigParser
from eduid_common.config.parsers.decorators import decrypt, interpolate


class YamlConfigParser(BaseConfigParser):
    def __init__(self, path: Path, ns: str, app_name: str):
        self.path = path
        self.ns = ns
        self.app_name = app_name

    @interpolate
    @decrypt
    def read_configuration(self) -> Mapping[str, Any]:
        with self.path.open() as fd:
            import yaml

            data = yaml.safe_load(fd)

        # traverse the loaded data to the right namespace, discarding everything else
        for this in self.ns.split('/'):
            if not this:
                continue
            data = data[this]

        config: Dict[str, Any] = {}
        if 'common' in data:
            config.update(data['common'])
        if self.app_name in data:
            config.update(data[self.app_name])

        if 'app_name' not in config:
            config['app_name'] = self.app_name

        return config
