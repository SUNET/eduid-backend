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

#import bson
import copy
import datetime

from eduid_userdb.exceptions import UserHasUnknownData, UserDBValueError, EduIDUserDBError

__author__ = 'ft'


class PrimaryMailAddressViolation(EduIDUserDBError):
    """
    Raised when some operation would result in more or less than one 'primary'
    e-mail address in an MailAddressList.
    """
    pass


class DuplicateMailAddressViolation(EduIDUserDBError):
    """
    Raised when some operation would result in duplicate e-mail addresses in a list.
    """
    pass


class MailAddress(object):
    """
    :param data: Mail address parameters from database
    :param raise_on_unknown: Raise exception on unknown values in `data' or not.

    :type data: dict
    :type raise_on_unknown: bool
    """
    def __init__(self, data, raise_on_unknown = True):
        if not isinstance(data, dict):
            raise UserDBValueError("Invalid 'data', not dict ({!r})".format(type(data)))
        self._data = {}
        data_in = data
        data = copy.copy(data_in)  # to not modify callers dict below
        #if 'id' not in data:
        #    # old-style mailAliases dicts don't have explicit ids
        #    data['id'] = bson.ObjectId
        #self.id = data.pop('id')
        self.email = data.pop('email')
        self.is_primary = data.pop('primary', False)
        self.is_verified = data.pop('verified', False)
        self.verified_by = data.pop('verified_by', None)
        self.verified_ts = data.pop('verified_ts', None)
        self.created_by = data.pop('created_by', None)
        self.created_ts = data.pop('created_ts', None)

        if len(data) > 0:
            if raise_on_unknown:
                raise UserHasUnknownData('MailAddress {!r} unknown data: {!r}'.format(
                    self.email, data.keys()
                ))
            # Just keep everything that is left as-is
            self._data.update(data)

    # -----------------------------------------------------------------
    #@property
    #def id(self):
    #    """
    #    This is a reference to the mail address in the authentication backend private database.
    #
    #    :return: Unique ID of mail address.
    #    :rtype: str
    #    """
    #    return self._data['id']
    #
    #@id.setter
    #def id(self, value):
    #    """
    #    :param value: Unique ID of mail address.
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
    def email(self):
        """
        This is a reference to the mail address in the authentication backend private database.

        :return: Unique ID of mail address.
        :rtype: str
        """
        return self._data['email']

    @email.setter
    def email(self, value):
        """
        :param value: e-mail address.
        :type value: str | unicode
        """
        if not isinstance(value, basestring):
            raise UserDBValueError("Invalid 'e-mail': {!r}".format(value))
        self._data['email'] = str(value.lower())

    # -----------------------------------------------------------------
    @property
    def is_primary(self):
        """
        :return: True if this is the primary e-mail address.
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
        :return: True if this is a verified e-mail address.
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
            raise PrimaryMailAddressViolation("Can't remove verified status of primary e-mail address")
        self._data['verified'] = value

    # -----------------------------------------------------------------
    @property
    def verified_by(self):
        """
        :return: Information about who verified the mail address.
        :rtype: str | unicode
        """
        return self._data.get('verified_by', '')

    @verified_by.setter
    def verified_by(self, value):
        """
        :param value: Information about who verified a mail address (None is no-op).
        :type value: str | unicode | None
        """
        if self._data.get('verified_by') is not None:
            # Once verified_by is set, it should not be modified.
            raise UserDBValueError("Refusing to modify verified_by of mail address")
        if value is None:
            return
        if not isinstance(value, basestring):
            raise UserDBValueError("Invalid 'verified_by' value: {!r}".format(value))
        self._data['verified_by'] = str(value)

    # -----------------------------------------------------------------
    @property
    def verified_ts(self):
        """
        :return: Timestamp of mail address verification.
        :rtype: datetime.datetime
        """
        return self._data.get('verified_ts')

    @verified_ts.setter
    def verified_ts(self, value):
        """
        :param value: Timestamp of mail address verification.
                      Value None is ignored, True is short for datetime.utcnow().
        :type value: datetime.datetime | True | None
        """
        if self._data.get('verified_ts') is not None:
            # Once verified_ts is set, it should not be modified.
            raise UserDBValueError("Refusing to modify verified_ts of mail address")
        if value is None:
            return
        if value is True:
            value = datetime.datetime.utcnow()
        self._data['verified_ts'] = value

    # -----------------------------------------------------------------
    @property
    def created_by(self):
        """
        :return: Information about who created the mail address (None is no-op).
        :rtype: str | unicode | None
        """
        return self._data.get('created_by')

    @created_by.setter
    def created_by(self, value):
        """
        :param value: Information about who created a mail address.
        :type value: str | unicode
        """
        if self._data.get('created_by') is not None:
            # Once created_by is set, it should not be modified.
            raise UserDBValueError("Refusing to modify created_by of mail address")
        if value is None:
            return
        if not isinstance(value, basestring):
            raise UserDBValueError("Invalid 'created_by' value: {!r}".format(value))
        self._data['created_by'] = str(value)

    # -----------------------------------------------------------------
    @property
    def created_ts(self):
        """
        :return: Timestamp of mail address creation.
        :rtype: datetime.datetime
        """
        return self._data.get('created_ts')

    @created_ts.setter
    def created_ts(self, value):
        """
        :param value: Timestamp of mail address creation.
                      Value None is ignored, True is short for datetime.utcnow().
        :type value: datetime.datetime | True | None
        """
        if self._data.get('created_ts') is not None:
            # Once created_ts is set, it should not be modified.
            raise UserDBValueError("Refusing to modify created_ts of mail address")
        if value is None:
            return
        if value is True:
            value = datetime.datetime.utcnow()
        self._data['created_ts'] = value

    # -----------------------------------------------------------------
    def to_dict(self):
        """
        Convert MailAddress to a dict, that can be used to reconstruct the
        MailAddress later.
        """
        return self._data


class MailAddressList(object):
    """
    Hold a list of MailAddress instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary e-mail address in the list (except if the list is empty).

    :param addresses: List of e-mail addresses
    :type addresses: [dict | MailAddress]
    """
    def __init__(self, addresses, raise_on_unknown = True):
        self._addresses = []

        for this in addresses:
            if isinstance(this, MailAddress):
                address = this
            else:
                address = address_from_dict(this, raise_on_unknown)
            self._addresses.append(address)

        try:
            if self._addresses:
                assert _get_primary(self._addresses) is not None
        except PrimaryMailAddressViolation:
            raise PrimaryMailAddressViolation("Operation would result in more or less than one primary address")

    def to_list(self):
        """
        Return the list of addresss as an iterable.
        :return: List of addresss
        :rtype: [MailAddress]
        """
        return self._addresses

    def to_list_of_dicts(self):
        """
        Get the addresss in a serialized format that can be stored in MongoDB.

        :return: List of dicts
        :rtype: [dict]
        """
        return [this.to_dict() for this in self._addresses]

    def find(self, email):
        """
        Find an MailAddress from the address list, using the e-mail address.

        :param email: the email addresses to look for
        :type  email: str | unicode
        """
        if not isinstance(email, basestring):
            raise UserDBValueError("Invalid 'e-mail': {!r}".format(email))

        res = [x for x in self._addresses if x.email == email]
        if len(res) == 1:
            return res[0]
        if len(res) > 1:
            raise EduIDUserDBError("More than one e-mail address found")
        return False

    def add(self, address):
        """
        Add a MailAddress to the list.

        Raises PrimaryMailAddressViolation if the operation results in != 1 primary
        e-mail address in the list.

        Raises DuplicateMailAddressViolation if the e-mail address already exist in
        the list.

        :param address: MailAddress
        :return: MailAddressList
        """
        if not isinstance(address, MailAddress):
            raise UserDBValueError("Invalid MailAddress: {!r}".format(address))

        if self.find(address.email):
            raise DuplicateMailAddressViolation("Address {!s} already in list".format(address.email))

        new_list = self._addresses + [address]
        try:
            assert _get_primary(new_list) is not None
        except PrimaryMailAddressViolation:
            raise PrimaryMailAddressViolation("Operation would result in more or less than one primary address")
        self._addresses = new_list
        return self._addresses

    # Not sure there is a use case for MailAddressList.update
    #def update(self, address):
    #    """
    #    Update an existing MailAddress in the list.
    #
    #    Raises PrimaryMailAddressViolation if the operation results in != 1 primary
    #    e-mail address in the list.
    #
    #    :param address: MailAddress
    #    :return: MailAddressList
    #    """
    #    if not isinstance(address, MailAddress):
    #        raise UserDBValueError("Invalid MailAddress: {!r}".format(address))
    #
    #    found = False
    #    new_list = self._addresses
    #    for idx in xrange(len(self._addresses)):
    #        if self._addresses[idx].email == address.email:
    #            new_list[idx] = address
    #            found = True
    #            break
    #
    #    if not found:
    #        raise UserDBValueError("MailAddress not found in list")
    #
    #    try:
    #        assert _get_primary(new_list) is not None
    #    except PrimaryMailAddressViolation:
    #        raise PrimaryMailAddressViolation("Operation would result in more or less than one primary address")
    #    self._addresses = new_list
    #    return self

    def remove(self, email):
        """
        Remove an existing MailAddress from the list.

        Raises PrimaryMailAddressViolation if the operation results in != 1 primary
        e-mail address in the list.

        :param email: E-mail address to remove
        :type email: str | unicode
        :return: MailAddressList
        """
        match = self.find(email)
        if not match:
            raise UserDBValueError("MailAddress not found in list")

        new_list = [this for this in self._addresses if this != match]

        try:
            if new_list:
                assert _get_primary(new_list) is not None
        except PrimaryMailAddressViolation:
            raise PrimaryMailAddressViolation("Operation would result in more or less than one primary address")
        self._addresses = new_list
        return self

    @property
    def primary(self):
        """
        :return: Return the primary MailAddress.

        There must always be exactly one primary e-mail address in the list, so an
        PrimaryMailAddressViolation is raised in case this assertion does not hold.

        :rtype: MailAddress
        """
        return _get_primary(self._addresses)

    @primary.setter
    def primary(self, email):
        """
        Mark e-mail address as the users primary e-mail address.

        This is a MailAddressList operation since it needs to atomically update more than one
        address in the list. Marking an address as primary will result in some other address
        loosing it's primary status.

        :param email: the email addresses to set as primary
        :type  email: str | unicode
        """
        match = self.find(email)

        if not match:
            raise UserDBValueError("E-mail address not found in list, can't set as primary")

        if not match.is_verified:
            raise PrimaryMailAddressViolation("Primary e-mail address must be verified")

        # go through the whole list. Mark email as primary and all other as *not* primary.
        for this in self._addresses:
            this.is_primary = bool(this.email == email)


def _get_primary(addresses):
    """
    Find the primary e-mail address in a list, and ensure there is exactly one (unless the list is empty).

    :param addresses: List of MailAddress instances
    :type addresses: [MailAddress]
    :return: Primary MailAddress
    :rtype: MailAddress | None
    """
    if not addresses:
        return None
    res = [x for x in addresses if x.is_primary is True]
    if len(res) != 1:
        raise PrimaryMailAddressViolation("List contains {!s}/{!s} primary e-mail addresses".format(
            len(res), len(addresses)))
    if not res[0].is_verified:
        raise PrimaryMailAddressViolation("Primary e-mail address must be verified")
    return res[0]


def address_from_dict(data, raise_on_unknown = True):
    """
    Create a MailAddress instance from a dict.

    :param data: Mail address parameters from database
    :param raise_on_unknown: Raise exception on unknown values in `data' or not.

    :type data: dict
    :type raise_on_unknown: bool
    :rtype: MailAddress
    """
    return MailAddress(data, raise_on_unknown)
