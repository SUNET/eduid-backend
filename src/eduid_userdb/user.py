#
# Copyright (c) 2014-2015 NORDUnet A/S
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

from eduid_userdb.exceptions import EduIDUserDBError, UserDBValueError

from eduid_userdb.mail import MailAddressList
from eduid_userdb.phone import PhoneNumberList
from eduid_userdb.password import PasswordList

from eduid_userdb.exceptions import UserHasUnknownData


class User(object):
    """
    Generic eduID user object.

    :param data: MongoDB document representing a user
    :type  data: dict
    """
    def __init__(self, data, raise_on_unknown = False):
        data_in = data
        data = copy.copy(data_in)  # to not modify callers data
        self._data = dict()
        # things without setters
        self._data['_id'] = data.pop('_id')
        _mail_addresses = data.pop('mailAliases', [])
        for idx in xrange(len(_mail_addresses)):
            if _mail_addresses[idx]['email'] == data['mail']:
                _mail_addresses[idx]['primary'] = True
        data.pop('mail')
        self._mail_addresses = MailAddressList(_mail_addresses)
        self._phone_numbers = PhoneNumberList(data.pop('mobile', []))
        self._passwords = PasswordList(data.pop('passwords'))

        if len(data) > 0:
            if raise_on_unknown:
                raise UserHasUnknownData('User {!s}/{!s} unknown data: {!r}'.format(
                    self.user_id, self.eppn, data.keys()
                ))
            # Just keep everything that is left as-is
            self._data.update(data)

    def __repr__(self):
        return '<eduID User: {!s}/{!s}>'.format(self.eppn, self.user_id)

    @property
    def user_id(self):
        """
        Get the user's oid in MongoDB.

        :rtype: bson.ObjectId
        """
        return self._data['_id']

    @property
    def eppn(self):
        """
        Get the user's eduPersonPrincipalName.

        :rtype: str
        """
        return self._data.get('eduPersonPrincipalName', '')

    @eppn.setter
    def eppn(self, eppn):
        """
        :param eppn: Set the user's eduPersonPrincipalName.
        :type eppn: str | unicode
        """
        if self._data.get('eduPersonPrincipalName') is not None:
            raise UserDBValueError('Overwriting an existing eduPersonPrincipalName is not allowed')
        self._data['eduPersonPrincipalName'] = eppn

    @property
    def given_name(self):
        """
        Get the user's givenName.

        :rtype: str | unicode
        """
        return self._data.get('givenName', '')

    @given_name.setter
    def given_name(self, name):
        """
        Set the user's givenName.

        :param name: the givenName to set
        :type  name: str | unicode
        """
        self._data['givenName'] = name

    @property
    def display_name(self):
        """
        Get the user's displayName.

        :rtype: str | unicode
        """
        return self._data.get('displayName', '')

    @display_name.setter
    def display_name(self, name):
        """
        Set the user's displayName.

        :param name: the displayName to set
        :type  name: str
        """
        self._data['displayName'] = name

    @property
    def sn(self):
        """
        Get the user's sn (family name).

        :rtype: str | unicode
        """
        return self._data.get('sn', '')

    @sn.setter
    def sn(self, sn):
        """
        Set the user's sn (family name).

        :param sn: the sn to set
        :type  sn: str
        """
        self._data['sn'] = sn

    @property
    def mail_addresses(self):
        """
        Get the user's email addresses.
        :return: MailAddressList object
        :rtype: eduid_userdb.mail.MailAddressList
        """
        # no setter for this one, as the MailAddressList object provides modification functions
        return self._mail_addresses

    @property
    def phone_numbers(self):
        """
        Get the user's phone numbers.
        :return: PhoneNumberList object
        :rtype: eduid_userdb.phone.PhoneNumberList
        """
        # no setter for this one, as the PhoneNumberList object provides modification functions
        return self._phone_numbers

    @property
    def passwords(self):
        """
        Get the user's phone numbers.
        :return: PasswordList object
        :rtype: eduid_userdb.password.PasswordList
        """
        # no setter for this one, as the PasswordList object provides modification functions
        return self._passwords
