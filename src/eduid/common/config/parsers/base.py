from abc import ABC

__author__ = "lundberg"

from typing import Any
from collections.abc import Mapping


class BaseConfigParser(ABC):
    def read_configuration(self, path: str) -> Mapping[str, Any]:
        raise NotImplementedError()
