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
from eduid_userdb.exceptions import EduIDUserDBError, UserHasUnknownData, UserDBValueError


class PrimaryElementError(EduIDUserDBError):
    pass

class PrimaryElementViolation(PrimaryElementError):
    """
    Raised when some operation would result in more or less than one 'primary'
    e-mail element in an MailelementList.
    """
    pass


class DuplicatePrimaryElementViolation(PrimaryElementError):
    """
    Raised when some operation would result in duplicate e-mail elements in a list.
    """
    pass


class PrimaryElement(object):
    """
    :param data: Mail element parameters from database
    :param raise_on_unknown: Raise exception on unknown values in `data' or not.

    :type data: dict
    :type raise_on_unknown: bool
    """
    def __init__(self, data, raise_on_unknown = True, ignore_data = []):
        if not isinstance(data, dict):
            raise UserDBValueError("Invalid 'data', not dict ({!r})".format(type(data)))
        self._data = {}
        data_in = data
        data = copy.copy(data_in)  # to not modify callers dict below
        #if 'id' not in data:
        #    # old-style mailAliases dicts don't have explicit ids
        #    data['id'] = bson.ObjectId
        #self.id = data.pop('id')
        self.is_primary = data.pop('primary', False)
        self.is_verified = data.pop('verified', False)
        self.verified_by = data.pop('verified_by', None)
        self.verified_ts = data.pop('verified_ts', None)
        self.created_by = data.pop('created_by', None)
        self.created_ts = data.pop('created_ts', None)

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
    def key(self):
        """
        Return the element that is used as key in a PrimaryElementList.
        Must be implemented in subclasses of PrimaryElement.
        """
        raise NotImplementedError("'key' not implemented for PrimaryElement subclass")

    # -----------------------------------------------------------------
    #@property
    #def id(self):
    #    """
    #    This is a reference to the mail element in the authentication backend private database.
    #
    #    :return: Unique ID of mail element.
    #    :rtype: str
    #    """
    #    return self._data['id']
    #
    #@id.setter
    #def id(self, value):
    #    """
    #    :param value: Unique ID of mail element.
    #    :type value: str | unicode
    #    """
    #    if isinstance(value, bson.ObjectId):
    #        value = str(value)
    #    if not isinstance(value, basestring):
    #        raise UserDBValueError("Invalid 'id': {!r}".format(value))
    #    self._data['id'] = str(value)
    #

    # -----------------------------------------------------------------
    @property
    def is_primary(self):
        """
        :return: True if this is the primary e-mail element.
        :rtype: bool
        """
        return self._data['primary']

    @is_primary.setter
    def is_primary(self, value):
        """
        :param value: New verification status
        :type value: bool
        """
        if not isinstance(value, bool):
            raise UserDBValueError("Invalid 'primary': {!r}".format(value))
        self._data['primary'] = value

    # -----------------------------------------------------------------
    @property
    def is_verified(self):
        """
        :return: True if this is a verified e-mail element.
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
            raise UserDBValueError("Invalid 'verified': {!r}".format(value))
        if value is False and self.is_primary:
            raise PrimaryElementViolation("Can't remove verified status of primary e-mail element")
        self._data['verified'] = value

    # -----------------------------------------------------------------
    @property
    def verified_by(self):
        """
        :return: Information about who verified the mail element.
        :rtype: str | unicode
        """
        return self._data.get('verified_by', '')

    @verified_by.setter
    def verified_by(self, value):
        """
        :param value: Information about who verified a mail element (None is no-op).
        :type value: str | unicode | None
        """
        if self._data.get('verified_by') is not None:
            # Once verified_by is set, it should not be modified.
            raise UserDBValueError("Refusing to modify verified_by of mail element")
        if value is None:
            return
        if not isinstance(value, basestring):
            raise UserDBValueError("Invalid 'verified_by' value: {!r}".format(value))
        self._data['verified_by'] = str(value)

    # -----------------------------------------------------------------
    @property
    def verified_ts(self):
        """
        :return: Timestamp of mail element verification.
        :rtype: datetime.datetime
        """
        return self._data.get('verified_ts')

    @verified_ts.setter
    def verified_ts(self, value):
        """
        :param value: Timestamp of mail element verification.
                      Value None is ignored, True is short for datetime.utcnow().
        :type value: datetime.datetime | True | None
        """
        if self._data.get('verified_ts') is not None:
            # Once verified_ts is set, it should not be modified.
            raise UserDBValueError("Refusing to modify verified_ts of mail element")
        if value is None:
            return
        if value is True:
            value = datetime.datetime.utcnow()
        self._data['verified_ts'] = value

    # -----------------------------------------------------------------
    @property
    def created_by(self):
        """
        :return: Information about who created the mail element (None is no-op).
        :rtype: str | unicode | None
        """
        return self._data.get('created_by')

    @created_by.setter
    def created_by(self, value):
        """
        :param value: Information about who created a mail element.
        :type value: str | unicode
        """
        if self._data.get('created_by') is not None:
            # Once created_by is set, it should not be modified.
            raise UserDBValueError("Refusing to modify created_by of mail element")
        if value is None:
            return
        if not isinstance(value, basestring):
            raise UserDBValueError("Invalid 'created_by' value: {!r}".format(value))
        self._data['created_by'] = str(value)

    # -----------------------------------------------------------------
    @property
    def created_ts(self):
        """
        :return: Timestamp of mail element creation.
        :rtype: datetime.datetime
        """
        return self._data.get('created_ts')

    @created_ts.setter
    def created_ts(self, value):
        """
        :param value: Timestamp of mail element creation.
                      Value None is ignored, True is short for datetime.utcnow().
        :type value: datetime.datetime | True | None
        """
        if self._data.get('created_ts') is not None:
            # Once created_ts is set, it should not be modified.
            raise UserDBValueError("Refusing to modify created_ts of mail element")
        if value is None:
            return
        if value is True:
            value = datetime.datetime.utcnow()
        self._data['created_ts'] = value

    # -----------------------------------------------------------------
    def to_dict(self):
        """
        Convert Mailelement to a dict, that can be used to reconstruct the
        Mailelement later.
        """
        return self._data


class PrimaryElementList(object):
    """
    Hold a list of Mailelement instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary e-mail element in the list (except if the list is empty).

    :param elements: List of e-mail elements
    :type elements: [dict | Mailelement]
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
        :rtype: [Mailelement]
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
        Find an Mailelement from the element list, using the e-mail element.

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
        Add a Mailelement to the list.

        Raises PrimaryElementViolation if the operation results in != 1 primary
        e-mail element in the list.

        Raises DuplicatePrimaryElementViolation if the e-mail element already exist in
        the list.

        :param element: Mailelement
        :return: MailelementList
        """
        if not isinstance(element, PrimaryElement):
            raise UserDBValueError("Invalid Mailelement: {!r}".format(element))

        if self.find(element.key):
            raise DuplicatePrimaryElementViolation("element {!s} already in list".format(element.key))

        new_list = self._elements + [element]
        try:
            assert _get_primary(new_list) is not None
        except PrimaryElementViolation:
            raise PrimaryElementViolation("Operation would result in more or less than one primary element")
        self._elements = new_list
        return self._elements

    # Not sure there is a use case for MailelementList.update
    #def update(self, element):
    #    """
    #    Update an existing Mailelement in the list.
    #
    #    Raises PrimaryElementViolation if the operation results in != 1 primary
    #    e-mail element in the list.
    #
    #    :param element: Mailelement
    #    :return: MailelementList
    #    """
    #    if not isinstance(element, Mailelement):
    #        raise UserDBValueError("Invalid Mailelement: {!r}".format(element))
    #
    #    found = False
    #    new_list = self._elements
    #    for idx in xrange(len(self._elements)):
    #        if self._elements[idx].key == element.key:
    #            new_list[idx] = element
    #            found = True
    #            break
    #
    #    if not found:
    #        raise UserDBValueError("Mailelement not found in list")
    #
    #    try:
    #        assert _get_primary(new_list) is not None
    #    except PrimaryElementViolation:
    #        raise PrimaryElementViolation("Operation would result in more or less than one primary element")
    #    self._elements = new_list
    #    return self

    def remove(self, key):
        """
        Remove an existing Mailelement from the list.

        Raises PrimaryElementViolation if the operation results in != 1 primary
        e-mail element in the list.

        :param key: Key of element to remove
        :type key: str | unicode
        :return: MailelementList
        """
        match = self.find(key)
        if not match:
            raise UserDBValueError("Mailelement not found in list")

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
        :return: Return the primary Mailelement.

        There must always be exactly one primary e-mail element in the list, so an
        PrimaryElementViolation is raised in case this assertion does not hold.

        :rtype: Mailelement
        """
        return _get_primary(self._elements)

    @primary.setter
    def primary(self, key):
        """
        Mark e-mail element as the users primary e-mail element.

        This is a MailelementList operation since it needs to atomically update more than one
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

    :param elements: List of Mailelement instances
    :type elements: [Mailelement]
    :return: Primary Mailelement
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
