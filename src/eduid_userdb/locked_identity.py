# -*- coding: utf-8 -*-

from six import string_types

from eduid_userdb.element import Element, ElementList
from eduid_userdb.exceptions import UserDBValueError, EduIDUserDBError


__author__ = 'lundberg'


class LockedIdentityElement(Element):

    """
    Element that is used to lock an identity to a user

    Properties of LockedIdentityElement:

        identity_type
    """

    def __init__(self, data):
        Element.__init__(self, data)
        self.identity_type = data.pop('identity_type')

    # -----------------------------------------------------------------
    @property
    def key(self):
        """
        :return: Type of identity
        :rtype: string_types
        """
        return self.identity_type

    # -----------------------------------------------------------------
    @property
    def identity_type(self):
        """
        :return: Type of identity
        :rtype: string_types
        """
        return self._data['identity_type']

    @identity_type.setter
    def identity_type(self, value):
        """
        :param value: Type of identity
        :type value: string_types
        """
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'identity_type': {!r}".format(value))
        self._data['identity_type'] = value


class LockedIdentityNin(LockedIdentityElement):

    """
    Element that is used to lock a NIN to a user

    Properties of LockedNinElement:

        number
    """

    def __init__(self, number, created_by, created_ts):
        data = {
            'created_by': created_by,
            'created_ts': created_ts,
            'identity_type': 'nin'
        }
        LockedIdentityElement.__init__(self, data)
        self.number = number

    # -----------------------------------------------------------------
    @property
    def number(self):
        """
        :return: Nin number
        :rtype: string_types
        """
        return self._data['number']

    @number.setter
    def number(self, value):
        """
        :param value: Nin number
        :type value: string_types
        """
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'number': {!r}".format(value))
        self._data['number'] = value


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
            if isinstance(item, LockedIdentityList):
                elements.append(item)
            else:
                if item['identity_type'] == 'nin':
                    elements.append(LockedIdentityNin(number=item['number'], created_by=item['created_by'],
                                                      created_ts=item['created_ts']))
        ElementList.__init__(self, elements)

    def remove(self, key):
        """
        Override remove method as an element should be set once, remove never.
        """
        raise EduIDUserDBError('Removal of LockedIdentityElements is not permitted')
