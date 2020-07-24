# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Type

from eduid_userdb.element import Element, ElementList
from eduid_userdb.exceptions import EduIDUserDBError

__author__ = 'lundberg'


@dataclass
class _LockedIdentityElementRequired:
    """
    Required fields for LockedElement, so that they go before the optional
    arguments of Element in the implicit constructor.
    """

    identity_type: str


@dataclass
class LockedIdentityElement(Element, _LockedIdentityElementRequired):

    """
    Element that is used to lock an identity to a user

    Properties of LockedIdentityElement:

        identity_type
    """

    @property
    def key(self) -> str:
        """
        :return: Type of identity
        """
        # XXX this is wrong, with a list of locked identity elements we should be able to
        # XXX find or remove elements through their key, so the key should be unique for
        # XXX each locked identity element.
        return self.identity_type


@dataclass
class _LockedIdentityNinRequired:
    """
    Required fields for LockedElementNin, so that they go before the optional
    arguments of Element in the implicit constructor.
    """

    number: str


@dataclass
class LockedIdentityNin(LockedIdentityElement, _LockedIdentityNinRequired):

    """
    Element that is used to lock a NIN to a user

    Properties of LockedNinElement:

        number
    """

    identity_type: str = 'nin'

    @classmethod
    def data_in_transforms(cls: Type[LockedIdentityNin], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Construct locked identity element from a data dict.
        """
        data['identity_type'] = 'nin'

        data = super().data_in_transforms(data)

        return data


class LockedIdentityList(ElementList):
    """
    Hold a list of LockedIdentityElement instances.

    Provide methods to find and add to the list.

    :param locked_identities: List of LockedIdentityElements
    :type locked_identities: [dict | Element]
    """

    def __init__(self, locked_identities):
        elements = []
        for item in locked_identities:
            if isinstance(item, LockedIdentityElement):
                elements.append(item)
            else:
                if item['identity_type'] == 'nin':
                    elements.append(LockedIdentityNin.from_dict(item))
        ElementList.__init__(self, elements)

    def remove(self, key):
        """
        Override remove method as an element should be set once, remove never.
        """
        raise EduIDUserDBError('Removal of LockedIdentityElements is not permitted')
