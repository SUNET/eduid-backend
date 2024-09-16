from abc import ABC

__author__ = "lundberg"

from collections.abc import Mapping
from typing import Any


class BaseConfigParser(ABC):
    def read_configuration(self, path: str) -> Mapping[str, Any]:
        raise NotImplementedError()
