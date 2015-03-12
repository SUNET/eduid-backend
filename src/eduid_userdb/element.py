#
# Copyright (c) 2015 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#

__author__ = 'ft'

import copy
import datetime

import eduid_userdb.util
from eduid_userdb.exceptions import EduIDUserDBError, UserHasUnknownData, UserDBValueError


class PrimaryElementError(EduIDUserDBError):
    """
    Base exception class for PrimaryElement errors.
    """
    pass


class PrimaryElementViolation(PrimaryElementError):
    """
    Raised when some operation would result in more or less than one 'primary'
    element in an PrimaryElementList.
    """
    pass


class DuplicatePrimaryElementViolation(PrimaryElementError):
    """
    Raised when some operation would result in duplicate elements in a list.
    """
    pass


class Element(object):
    """
    Base class for elements.

    Hierarchy:

        Element
            VerifiedElement
                PrimaryElement

    Properties of Element:

        created_by
        created_ts
    """
    def __init__(self, data):
        if not isinstance(data, dict):
            raise UserDBValueError("Invalid 'data', not dict ({!r})".format(type(data)))
        self._data = {}

        self.created_by = data.pop('created_by', None)
        self.created_ts = data.pop('created_ts', None)

    # -----------------------------------------------------------------
    @property
    def key(self):
        """
        Return the element that is used as key in a PrimaryElementList.
        Must be implemented in subclasses of PrimaryElement.
        """
        raise NotImplementedError("'key' not implemented for Element subclass")

    # -----------------------------------------------------------------
    @property
    def created_by(self):
        """
        :return: Information about who created the element (None is no-op).
        :rtype: str | unicode | None
        """
        return self._data.get('created_by')

    @created_by.setter
    def created_by(self, value):
        """
        :param value: Information about who created a element.
        :type value: str | unicode
        """
        _update_something_by(self._data, 'created_by', value)

    # -----------------------------------------------------------------
    @property
    def created_ts(self):
        """
        :return: Timestamp of element creation.
        :rtype: datetime.datetime
        """
        return self._data.get('created_ts')

    @created_ts.setter
    def created_ts(self, value):
        """
        :param value: Timestamp of element creation.
                      Value None is ignored, True is short for datetime.utcnow().
        :type value: datetime.datetime | True | None
        """
        _update_something_by(self._data, 'created_ts', value)


class VerifiedElement(Element):
    """
    Elements that can be verified or not.

    Properties of VerifiedElement:

        is_verified
        verified_by
        verified_ts
    """

    def __init__(self, data):
        Element.__init__(self, data)
        self.is_verified = data.pop('verified', False)
        self.verified_by = data.pop('verified_by', None)
        self.verified_ts = data.pop('verified_ts', None)

    # -----------------------------------------------------------------
    @property
    def is_verified(self):
        """
        :return: True if this is a verified element.
        :rtype: bool
        """
        return self._data['verified']

    @is_verified.setter
    def is_verified(self, value):
        """
        :param value: New verification status
        :type value: bool
        """
        if not isinstance(value, bool):
            raise UserDBValueError("Invalid 'is_verified': {!r}".format(value))
        self._data['verified'] = value

    # -----------------------------------------------------------------
    @property
    def verified_by(self):
        """
        :return: Information about who verified the element.
        :rtype: str | unicode
        """
        return self._data.get('verified_by', '')

    @verified_by.setter
    def verified_by(self, value):
        """
        :param value: Information about who verified a element (None is no-op).
        :type value: str | unicode | None
        """
        _update_something_by(self._data, 'verified_by', value)

    # -----------------------------------------------------------------
    @property
    def verified_ts(self):
        """
        :return: Timestamp of element verification.
        :rtype: datetime.datetime
        """
        return self._data.get('verified_ts')

    @verified_ts.setter
    def verified_ts(self, value):
        """
        :param value: Timestamp of element verification.
                      Value None is ignored, True is short for datetime.utcnow().
        :type value: datetime.datetime | True | None
        """
        _update_something_ts(self._data, 'verified_ts', value)


class PrimaryElement(VerifiedElement):
    """
    Elements that can be either primary or not.

    Properties of PrimaryElement:

        is_primary

    :param data: element parameters from database
    :param raise_on_unknown: Raise exception on unknown values in `data' or not.

    :type data: dict
    :type raise_on_unknown: bool
    """
    def __init__(self, data, raise_on_unknown = True, ignore_data = []):
        data_in = data
        data = copy.copy(data_in)  # to not modify callers data

        VerifiedElement.__init__(self, data)

        self.is_primary = data.pop('primary', False)

        leftovers = [x for x in data.keys() if x not in ignore_data]
        if leftovers:
            if raise_on_unknown:
                raise UserHasUnknownData('PrimaryElement {!r} unknown data: {!r}'.format(
                    self.key, leftovers,
                ))
            # Just keep everything that is left as-is
            self._data.update(data)

    # -----------------------------------------------------------------
    @property
    def is_primary(self):
        """
        :return: True if this is the primary element.
        :rtype: bool
        """
        try:
            return self._data['primary']
        except KeyError:
            # handle init moment 22
            return False

    @is_primary.setter
    def is_primary(self, value):
        """
        :param value: New verification status
        :type value: bool
        """
        if not isinstance(value, bool):
            raise UserDBValueError("Invalid 'is_primary': {!r}".format(value))
        self._data['primary'] = value

    # -----------------------------------------------------------------
    @property
    def is_verified(self):
        """
        :return: True if this is a verified element.
        :rtype: bool
        """
        return self._data['verified']

    @is_verified.setter
    def is_verified(self, value):
        """
        :param value: New verification status
        :type value: bool
        """
        if not isinstance(value, bool):
            raise UserDBValueError("Invalid 'is_verified': {!r}".format(value))
        if value is False and self.is_primary:
            raise PrimaryElementViolation("Can't remove verified status of primary element")
        self._data['verified'] = value
    # -----------------------------------------------------------------

    def to_dict(self):
        """
        Convert Element to a dict, that can be used to reconstruct the
        Element later.
        """
        return self._data


class ElementList(object):
    """
    Hold a list of Element instances.

    Provide methods to find, add and remove elements from the list.

    :param elements: List of elements
    :type elements: [dict | Element]
    """
    def __init__(self, elements):
        for this in elements:
            if not isinstance(this, Element):
                raise ValueError("Not an Element")
        self._elements = elements

    def to_list(self):
        """
        Return the list of elements as an iterable.
        :return: List of elements
        :rtype: [Element]
        """
        return self._elements

    def to_list_of_dicts(self):
        """
        Get the elements in a serialized format that can be stored in MongoDB.

        :return: List of dicts
        :rtype: [dict]
        """
        return [this.to_dict() for this in self._elements]

    def find(self, key):
        """
        Find an Element from the element list, using the key.

        :param key: the key to look for in the list of elements
        """
        res = [x for x in self._elements if x.key == key]
        if len(res) == 1:
            return res[0]
        if len(res) > 1:
            raise EduIDUserDBError("More than one element found")
        return False

    def add(self, element):
        """
        Add a element to the list.

        :param element: Element
        :type element: PrimaryElement
        :return: PrimaryElementList
        """
        if not isinstance(element, Element):
            raise UserDBValueError("Invalid element: {!r}".format(element))

        self._elements.append(element)
        return self

    def remove(self, key):
        """
        Remove an existing Element from the list.

        :param key: Key of element to remove
        :return: ElementList
        """
        match = self.find(key)
        if not match:
            raise UserDBValueError("Element not found in list")

        self._elements = [this for this in self._elements if this != match]
        return self


class PrimaryElementList(ElementList):
    """
    Hold a list of Element instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary element in the list (except if the list is empty).

    :param elements: List of elements
    :type elements: [dict | Element]
    """
    def __init__(self, elements):
        try:
            if elements:
                assert _get_primary(elements) is not None
        except PrimaryElementViolation:
            raise PrimaryElementViolation("Operation would result in more or less than one primary element")
        self._elements = elements

    def to_list(self):
        """
        Return the list of elements as an iterable.
        :return: List of elements
        :rtype: [Element]
        """
        return self._elements

    def to_list_of_dicts(self):
        """
        Get the elements in a serialized format that can be stored in MongoDB.

        :return: List of dicts
        :rtype: [dict]
        """
        return [this.to_dict() for this in self._elements]

    def find(self, key):
        """
        Find an Element from the element list, using the key.

        :param key: the key to look for in the list of elements
        :type  key: str | unicode
        """
        res = [x for x in self._elements if x.key == key]
        if len(res) == 1:
            return res[0]
        if len(res) > 1:
            raise EduIDUserDBError("More than one element found")
        return False

    def add(self, element):
        """
        Add a element to the list.

        Raises PrimaryElementViolation if the operation results in != 1 primary
        element in the list.

        Raises DuplicatePrimaryElementViolation if the element already exist in
        the list.

        :param element: Element
        :type element: PrimaryElement
        :return: PrimaryElementList
        """
        if not isinstance(element, PrimaryElement):
            raise UserDBValueError("Invalid Element: {!r}".format(element))

        if self.find(element.key):
            raise DuplicatePrimaryElementViolation("element {!s} already in list".format(element.key))

        new_list = self._elements + [element]
        try:
            assert _get_primary(new_list) is not None
        except PrimaryElementViolation:
            raise PrimaryElementViolation("Operation would result in more or less than one primary element")
        self._elements = new_list
        return self

    def remove(self, key):
        """
        Remove an existing Element from the list.

        Raises PrimaryElementViolation if the operation results in != 1 primary
        element in the list.

        :param key: Key of element to remove
        :type key: str | unicode
        :return: ElementList
        """
        match = self.find(key)
        if not match:
            raise UserDBValueError("Element not found in list")

        new_list = [this for this in self._elements if this != match]

        try:
            if new_list:
                assert _get_primary(new_list) is not None
        except PrimaryElementViolation:
            raise PrimaryElementViolation("Operation would result in more or less than one primary element")
        self._elements = new_list
        return self

    @property
    def primary(self):
        """
        :return: Return the primary Element.

        There must always be exactly one primary element in the list, so an
        PrimaryElementViolation is raised in case this assertion does not hold.

        :rtype: Element
        """
        return _get_primary(self._elements)

    @primary.setter
    def primary(self, key):
        """
        Mark element as the users primary element.

        This is a ElementList operation since it needs to atomically update more than one
        element in the list. Marking an element as primary will result in some other element
        loosing it's primary status.

        :param key: the key of the element to set as primary
        :type  key: str | unicode
        """
        match = self.find(key)

        if not match:
            raise UserDBValueError("Element not found in list, can't set as primary")

        if not match.is_verified:
            raise PrimaryElementViolation("Primary element must be verified")

        # Go through the whole list. Mark element as primary and all other as *not* primary.
        for this in self._elements:
            this.is_primary = bool(this.key == key)


def _get_primary(elements):
    """
    Find the primary element in a list, and ensure there is exactly one (unless the list is empty).

    :param elements: List of Element instances
    :type elements: [Element]
    :return: Primary Element
    :rtype: PrimaryElement | None
    """
    if not elements:
        return None
    res = [x for x in elements if x.is_primary is True]
    if len(res) != 1:
        raise PrimaryElementViolation("List contains {!s}/{!s} primary elements".format(
            len(res), len(elements)))
    if not res[0].is_verified:
        raise PrimaryElementViolation("Primary element must be verified")
    return res[0]


def _update_something_by(data, key, value):
    """
    Shared code to update 'verified_by', 'created_by' and similar properties.

    :param data: Where the data is stored
    :param key: Key name of the data
    :param value: Information about who did something (None is no-op).

    :type value: str | unicode | None
    """
    if data.get(key) is not None:
        # Once verified_by is set, it should not be modified.
        raise UserDBValueError("Refusing to modify verified_by of element")
    if value is None:
        return
    if not isinstance(value, basestring):
        raise UserDBValueError("Invalid 'verified_by' value: {!r}".format(value))
    data[key] = str(value)


def _update_something_ts(data, key, value):
    """
    Shared code to update 'verified_ts', 'created_ts' and similar properties.

    :param data: Where the data is stored
    :param key: Key name of the data
    :param value: Timestamp of element verification.
                  Value None is ignored, True is short for datetime.utcnow().
    :type value: datetime.datetime | True | None
    """
    if data.get(key) is not None:
        # Once verified_ts is set, it should not be modified.
        raise UserDBValueError("Refusing to modify verified_ts of element")
    if value is None:
        return
    if value is True:
        value = datetime.datetime.utcnow()
    data[key] = value
