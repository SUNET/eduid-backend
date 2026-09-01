import pytest

from eduid.common.config.parsers import _choose_parser
from eduid.common.config.parsers.yaml_parser import YamlConfigParser

__author__ = "lundberg"


class TestInitConfig:
    def test_YamlConfigParser(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EDUID_CONFIG_NS", "/test/ns/")
        monkeypatch.setenv("EDUID_CONFIG_YAML", "/config.yaml")
        parser = _choose_parser()
        assert isinstance(parser, YamlConfigParser)
