# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, asdict
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
    def key(self):
        """
        :return: Type of identity
        :rtype: string_types
        """
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
    def massage_data(cls: Type[LockedIdentityElement], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Construct locked identity element from a data dict.
        """
        data['identity_type'] = 'nin'

        data = super().massage_data(data)

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
                    elements.append(
                        LockedIdentityNin(
                            number=item['number'], created_by=item['created_by'], created_ts=item['created_ts']
                        )
                    )
        ElementList.__init__(self, elements)

    def remove(self, key):
        """
        Override remove method as an element should be set once, remove never.
        """
        raise EduIDUserDBError('Removal of LockedIdentityElements is not permitted')
