# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Optional
from uuid import UUID

from pydantic import BaseModel

from eduid.userdb.element import Element, ElementKey, VerifiedElement

__author__ = "lundberg"


class UniversityName(BaseModel):
    sv: str
    en: str


class University(Element):

    ladok_name: str
    name: UniversityName

    @property
    def key(self) -> ElementKey:
        """
        :return: Unique identifier
        """
        return ElementKey(self.ladok_name)


class Ladok(VerifiedElement):
    external_id: UUID
    university: University

    @property
    def key(self) -> ElementKey:
        """
        :return: Unique identifier
        """
        return ElementKey(str(self.external_id))
