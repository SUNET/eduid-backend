# -*- coding: utf-8 -*-

from __future__ import absolute_import

from abc import ABC

__author__ = 'lundberg'

from typing import Any, Mapping


class BaseConfigParser(ABC):
    def read_configuration(self) -> Mapping[str, Any]:
        raise NotImplementedError()
