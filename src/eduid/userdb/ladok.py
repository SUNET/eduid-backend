# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Optional
from uuid import UUID

from eduid.userdb.element import Element, ElementKey, VerifiedElement

__author__ = 'lundberg'


class University(Element):

    abbr: str  # university name abbreviation
    name_sv: str
    name_en: Optional[str]

    @property
    def key(self) -> ElementKey:
        """
        :return: Unique identifier
        """
        return ElementKey(self.abbr)


class Ladok(VerifiedElement):
    external_id: UUID
    university: University

    @property
    def key(self) -> ElementKey:
        """
        :return: Unique identifier
        """
        return ElementKey(str(self.external_id))
