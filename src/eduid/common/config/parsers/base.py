from abc import ABC, abstractmethod

__author__ = "lundberg"

from collections.abc import Mapping
from typing import Any


class BaseConfigParser(ABC):
    @abstractmethod
    def read_configuration(self, path: str) -> Mapping[str, Any]:
        raise NotImplementedError()
