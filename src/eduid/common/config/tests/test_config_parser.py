import os
from collections.abc import Iterator

import pytest

from eduid.common.config.parsers import _choose_parser
from eduid.common.config.parsers.yaml_parser import YamlConfigParser

__author__ = "lundberg"


class TestInitConfig:
    @pytest.fixture(autouse=True)
    def restore_env(self) -> Iterator[None]:
        saved = os.environ.copy()
        yield
        os.environ.clear()
        os.environ.update(saved)

    def test_YamlConfigParser(self) -> None:
        os.environ["EDUID_CONFIG_NS"] = "/test/ns/"
        os.environ["EDUID_CONFIG_YAML"] = "/config.yaml"
        parser = _choose_parser()
        assert isinstance(parser, YamlConfigParser)
