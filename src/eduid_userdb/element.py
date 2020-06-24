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
import copy
import datetime
import warnings
from typing import Any, Dict, List, Optional, Type, TypeVar, Union

from six import string_types

from eduid_userdb.exceptions import EduIDUserDBError, UserDBValueError, UserHasUnknownData

__author__ = 'ft'


class ElementError(EduIDUserDBError):
    """
    Base exception class for PrimaryElement errors.
    """

    pass


class DuplicateElementViolation(ElementError):
    """
    Raised when some operation would result in duplicate elements in a list.
    """

    pass


class PrimaryElementError(ElementError):
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


TElementSubclass = TypeVar('TElementSubclass', bound='Element')


class Element(object):
    """
    Base class for elements.

    Hierarchy:

        Element
            VerifiedElement
                PrimaryElement
            EventElement

    Properties of Element:

        created_by
        created_ts
    """

    def __init__(
        self, data: Dict[str, Any], called_directly: bool = True,
    ):
        raise NotImplementedError()

    def __str__(self):
        return '<eduID {!s}: {!r}>'.format(self.__class__.__name__, getattr(self, '_data', None))

    @classmethod
    def from_dict(cls: Type[TElementSubclass], data: Dict[str, Any]) -> TElementSubclass:
        """
        Construct element from a data dict.
        """
        if not isinstance(data, dict):
            raise UserDBValueError("Invalid 'data', not dict ({!r})".format(type(data)))

        self = object.__new__(cls)
        self._data: Dict[str, Any] = {}

        self.created_by = data.pop('created_by', None)
        self.created_ts = data.pop('created_ts', None)
        self.modified_ts = data.pop('modified_ts', None)

        return self

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
        _set_something_by(self._data, 'created_by', value)

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
        _set_something_ts(self._data, 'created_ts', value)

    # -----------------------------------------------------------------
    @property
    def modified_ts(self) -> Optional[datetime.datetime]:
        """
        :return: Timestamp of element last update.
        """
        return self._data.get('modified_ts')

    @modified_ts.setter
    def modified_ts(self, value: Optional[Union[datetime.datetime, bool]]):
        """
        :param value: Timestamp of element last update.
                      Value None is ignored, True is short for datetime.utcnow().
        """
        _set_something_ts(self._data, 'modified_ts', value, allow_update=True)

    # -----------------------------------------------------------------

    def to_dict(self, old_userdb_format=False):
        """
        Convert Element to a dict, that can be used to reconstruct the
        Element later.

        :param old_userdb_format: Set to True to get data back in legacy format.
        :type old_userdb_format: bool
        """
        res = copy.copy(self._data)  # avoid caller messing with our _data
        return res


class VerifiedElement(Element):
    """
    Elements that can be verified or not.

    Properties of VerifiedElement:

        is_verified
        verified_by
        verified_ts
    """

    def __init__(
        self, data: Dict[str, Any], called_directly: bool = True,
    ):
        raise NotImplementedError()

    @classmethod
    def from_dict(cls: Type[TElementSubclass], data: Dict[str, Any]) -> TElementSubclass:
        """
        Construct element from a data dict.
        """
        self = super().from_dict(data)
        # Remove deprecated verification_code from VerifiedElement
        data.pop('verification_code', None)
        self.is_verified = data.pop('verified', False)
        self.verified_by = data.pop('verified_by', None)
        self.verified_ts = data.pop('verified_ts', None)

        return self

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
        return self._data.get('verified_by', None)

    @verified_by.setter
    def verified_by(self, value):
        """
        :param value: Information about who verified a element (None is no-op).
        :type value: str | unicode | None
        """
        _set_something_by(self._data, 'verified_by', value, allow_update=True)

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
        _set_something_ts(self._data, 'verified_ts', value, allow_update=True)


TPrimaryElementSubclass = TypeVar('TPrimaryElementSubclass', bound='PrimaryElement')


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

    def __init__(
        self,
        data: Dict[str, Any],
        raise_on_unknown: bool = True,
        called_directly: bool = True,
        ignore_data: Optional[List[str]] = None,
    ):
        raise NotImplementedError()

    @classmethod
    def from_dict(
        cls: Type[TPrimaryElementSubclass], data: Dict[str, Any], raise_on_unknown: bool = True, ignore_data: Optional[Dict[str, Any]] = None
    ) -> TPrimaryElementSubclass:
        """
        Construct primary element from a data dict.
        """
        self = super().from_dict(data)

        self.is_primary = data.pop('primary', False)

        ignore_data = ignore_data or []
        leftovers = [x for x in data.keys() if x not in ignore_data]
        if leftovers:
            if raise_on_unknown:
                raise UserHasUnknownData('{!s} has unknown data: {!r}'.format(self.__class__.__name__, leftovers,))
            # Just keep everything that is left as-is
            self._data.update(data)

        return self

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
        return VerifiedElement.is_verified.fget(self)

    @is_verified.setter
    def is_verified(self, value):
        """
        :param value: New verification status
        :type value: bool
        """
        if value is False and self.is_primary:
            raise PrimaryElementViolation("Can't remove verified status of primary element")
        VerifiedElement.is_verified.fset(self, value)


class ElementList(object):
    """
    Hold a list of Element instances.

    Provide methods to find, add and remove elements from the list.

    :param elements: List of elements
    """

    def __init__(self, elements: List[Element]):
        for this in elements:
            if not isinstance(this, Element):
                raise ValueError("Not an Element")
        self._elements = elements

    def __repr__(self):
        return '<eduID {!s}: {!r}>'.format(self.__class__.__name__, getattr(self, '_elements', None))

    def to_list(self):
        """
        Return the list of elements as an iterable.
        :return: List of elements
        :rtype: [Element]
        """
        return self._elements

    def to_list_of_dicts(self, old_userdb_format=False):
        """
        Get the elements in a serialized format that can be stored in MongoDB.

        :param old_userdb_format: Set to True to get data back in legacy format.
        :type old_userdb_format: bool

        :return: List of dicts
        :rtype: [dict]
        """
        return [this.to_dict(old_userdb_format=old_userdb_format) for this in self._elements]

    def find(self, key):
        """
        Find an Element from the element list, using the key.

        :param key: the key to look for in the list of elements
        :return: Element found, or False if none was found
        :rtype: Element | False
        """
        res = [x for x in self._elements if x.key == key]
        if len(res) == 1:
            return res[0]
        if len(res) > 1:
            raise EduIDUserDBError("More than one element found")
        return False

    def add(self, element):
        """
        Add an element to the list.

        :param element: Element
        :type element: Element
        :return: ElementList
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

    def filter(self, cls):
        """
        Return a new ElementList with the elements that were instances of cls.

        :param cls: Class of interest
        :return: ElementList
        """
        return ElementList([x for x in self._elements if isinstance(x, cls)])

    @property
    def count(self):
        """
        Return the number of elements in the list
        """
        return len(self._elements)


class PrimaryElementList(ElementList):
    """
    Hold a list of Element instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary element in the list (except if the list is empty or there are
    no confirmed elements).

    :param elements: List of elements
    :type elements: [dict | Element]
    """

    def __init__(self, elements):
        self._get_primary(elements)
        ElementList.__init__(self, elements)

    def add(self, element):
        """
        Add a element to the list.

        Raises PrimaryElementViolation if the operation results in != 1 primary
        element in the list and there are confirmed elements.

        Raises DuplicateElementViolation if the element already exist in
        the list.

        :param element: PrimaryElement to add
        :type element: PrimaryElement
        :return: PrimaryElementList
        """
        if not isinstance(element, PrimaryElement):
            raise UserDBValueError("Invalid element: {!r}".format(element))

        if self.find(element.key):
            raise DuplicateElementViolation("Element {!s} already in list".format(element.key))

        old_list = self._elements
        ElementList.add(self, element)
        self._check_primary(old_list)
        return self

    def remove(self, key):
        """
        Remove an existing Element from the list.

        Raises PrimaryElementViolation if the operation results in 0 primary
        element in the list but there are confirmed elements.

        :param key: Key of element to remove
        :type key: str | unicode
        :return: ElementList
        """
        old_list = self._elements
        ElementList.remove(self, key)
        self._check_primary(old_list)
        return self

    @property
    def primary(self):
        """
        :return: Return the primary Element.

        There must always be exactly one primary element if there are confirmed
        elements in the list, and exactly zero if there are no confirmed elements, so a
        PrimaryElementViolation is raised in case any of these assertions do not hold.

        :rtype: PrimaryElement
        """
        return self._get_primary(self._elements)

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

    def _check_primary(self, old_list):
        """
        If there are confirmed elements, there must be exactly one primary
        element. If there are no confirmed elements, there must be 0 primary
        elements.

        :param old_list: list of elements to get back to if the constraints are violated
        :type old_list: list
        """
        try:
            self._get_primary(self._elements)
        except PrimaryElementViolation:
            self._elements = copy.copy(old_list)
            raise

    def _get_primary(self, elements):
        """
        Find the primary element in a list, and ensure there is exactly one (unless
        there are no confirmed elements, in which case, ensure there are exactly zero).

        :param elements: List of Element instances
        :type elements: [Element]
        :return: Primary Element
        :rtype: PrimaryElement | None
        """
        if not elements:
            return None
        verified = [x for x in elements if x.is_verified is True]

        if len(verified) == 0:
            if len([e for e in elements if e.is_primary]) > 0:
                raise PrimaryElementViolation('There are unconfirmed primary elements')
            return None

        res = [x for x in verified if x.is_primary is True]
        if len(res) != 1:
            raise PrimaryElementViolation(
                "{!s} contains {!s}/{!s} primary elements".format(self.__class__.__name__, len(res), len(elements))
            )
        return res[0]

    @property
    def verified(self):
        """
        get a PrimaryElementList with only the confirmed elements.
        """
        verified_elements = [e for e in self._elements if e.is_verified]
        return self.__class__(verified_elements)


def _set_something_by(data, key, value, allow_update=False):
    """
    Shared code to set or update 'verified_by', 'created_by' and similar properties.

    :param data: Where the data is stored
    :param key: Key name of the data
    :param value: Information about who did something (None is no-op).

    :type value: str | unicode | None
    """
    if data.get(key) is not None and not allow_update:
        # Once created_by etc. is set, it should not be modified.
        raise UserDBValueError("Refusing to modify {!r} of element".format(key))
    if value is None:
        return
    if not isinstance(value, string_types):
        raise UserDBValueError("Invalid {!r} value: {!r}".format(key, value))
    data[key] = str(value)


def _set_something_ts(data, key, value, allow_update=False):
    """
    Shared code to set or update 'verified_ts', 'created_ts' and similar properties.

    :param data: Where the data is stored
    :param key: Key name of the data
    :param value: Timestamp of element verification.
                  Value None is ignored, True is short for datetime.utcnow().
    :type value: datetime.datetime | True | None
    """
    if data.get(key) is not None and not allow_update:
        # Once created_ts etc. is set, it should not be modified.
        raise UserDBValueError("Refusing to modify {!r} of element".format(key))
    if value is None:
        return
    if value is True:
        value = datetime.datetime.utcnow()
    if not isinstance(value, datetime.datetime):
        raise UserDBValueError("Invalid {!r} value: {!r}".format(key, value))
    data[key] = value
