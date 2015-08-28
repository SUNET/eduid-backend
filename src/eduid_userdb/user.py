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

import bson
import copy
import datetime

from eduid_userdb.exceptions import UserHasUnknownData
from eduid_userdb.element import UserDBValueError

from eduid_userdb.mail import MailAddressList
from eduid_userdb.phone import PhoneNumberList
from eduid_userdb.password import PasswordList
from eduid_userdb.nin import NinList

VALID_SUBJECT_VALUES = ['physical person']


class User(object):
    """
    Generic eduID user object.

    :param data: MongoDB document representing a user
    :type  data: dict
    """
    def __init__(self, data, raise_on_unknown = True):
        data_in = data
        data = copy.deepcopy(data_in)  # to not modify callers data
        self._data = dict()
        # things without setters
        _id = data.pop('_id', None)
        if _id is None:
            _id = bson.ObjectId()
        if not isinstance(_id, bson.ObjectId):
            _id = bson.ObjectId(_id)
        self._data['_id'] = _id
        _mail_addresses = data.pop('mailAliases', [])
        if 'mail' in data:
            # old-style userdb primary e-mail address indicator
            for idx in xrange(len(_mail_addresses)):
                if _mail_addresses[idx]['email'] == data['mail']:
                    _mail_addresses[idx]['primary'] = True
            data.pop('mail')
        _nins = data.pop('nins', [])
        if 'norEduPersonNIN' in data:
            # old-style list of verified nins
            old_nins = data.pop('norEduPersonNIN')
            for this in old_nins:
                if isinstance(this, basestring):
                    # XXX lookup NIN in eduid-dashboards verifications to make sure it is verified somehow?
                    _primary = not _nins
                    _nins.append({'number': this,
                                  'primary': _primary,
                                  'verified': True,
                                  })
                elif isinstance(this, dict):
                    _nins.append({'number': this.pop('number'),
                                  'primary': this.pop('primary'),
                                  'verified': this.pop('verified'),
                                  })
                    if len(this):
                        raise UserDBValueError('Old-style NIN-as-dict has unknown data')
                else:
                    raise UserDBValueError('Old-style NIN is not a string or dict')

        if 'mobile' in data:
            data['phone'] = data.pop('mobile')
        if 'sn' in data:
            data['surname'] = data.pop('sn')
        if 'eduPersonEntitlement' in data:
            data['entitlements'] = data.pop('eduPersonEntitlement')
        self._mail_addresses = MailAddressList(_mail_addresses)
        self._phone_numbers = PhoneNumberList(data.pop('phone', []))
        self._nins = NinList(_nins)
        self._passwords = PasswordList(data.pop('passwords', []))
        # generic (known) attributes
        self.eppn = data.pop('eduPersonPrincipalName')  # mandatory
        self.subject = data.pop('subject', None)
        self.display_name = data.pop('displayName', '')
        self.given_name = data.pop('givenName', '')
        self.surname = data.pop('surname', '')
        self.language = data.pop('preferredLanguage', '')
        self.modified_ts = data.pop('modified_ts', None)
        self.entitlements = data.pop('entitlements', None)

        if len(data) > 0:
            if raise_on_unknown:
                raise UserHasUnknownData('User {!s}/{!s} unknown data: {!r}'.format(
                    self.user_id, self.eppn, data.keys()
                ))
            # Just keep everything that is left as-is
            self._data.update(data)

    def __repr__(self):
        return '<eduID {!s}: {!s}/{!s}>'.format(self.__class__.__name__,
                                                self.eppn,
                                                self.user_id,
                                                )

    def __eq__(self, other):
        return self._data == other._data

    # -----------------------------------------------------------------
    @property
    def user_id(self):
        """
        Get the user's oid in MongoDB.

        :rtype: bson.ObjectId
        """
        return self._data['_id']

    # -----------------------------------------------------------------
    @property
    def eppn(self):
        """
        Get the user's eduPersonPrincipalName.

        :rtype: str
        """
        return self._data.get('eduPersonPrincipalName', '')

    @eppn.setter
    def eppn(self, value):
        """
        :param value: Set the user's eduPersonPrincipalName.
        :type value: str | unicode
        """
        if self._data.get('eduPersonPrincipalName') is not None:
            raise UserDBValueError('Overwriting an existing eduPersonPrincipalName is not allowed')
        self._data['eduPersonPrincipalName'] = value

    # -----------------------------------------------------------------
    @property
    def given_name(self):
        """
        Get the user's givenName.

        :rtype: str | unicode
        """
        return self._data.get('givenName', '')

    @given_name.setter
    def given_name(self, value):
        """
        Set the user's givenName.

        :param value: the givenName to set
        :type  value: str | unicode
        """
        self._data['givenName'] = value

    # -----------------------------------------------------------------
    @property
    def display_name(self):
        """
        Get the user's displayName.

        :rtype: str | unicode
        """
        return self._data.get('displayName', '')

    @display_name.setter
    def display_name(self, value):
        """
        Set the user's displayName.

        :param value: the displayName to set
        :type  value: str
        """
        self._data['displayName'] = value

    # -----------------------------------------------------------------
    @property
    def surname(self):
        """
        Get the user's surname (family name).

        :rtype: str | unicode
        """
        return self._data.get('surname', '')

    @surname.setter
    def surname(self, value):
        """
        Set the user's surname (family name).

        :param value: the surname to set
        :type  value: str | unicode
        """
        self._data['surname'] = value

    # -----------------------------------------------------------------
    @property
    def subject(self):
        """
        Get the user's subject type ('physical person', ...).

        :rtype: str | unicode
        """
        return self._data.get('subject')

    @subject.setter
    def subject(self, value):
        """
        Set the user's subject type ('physical person', ...).

        :param value: the subject to set
        :type  value: str
        """
        if value is None:
            return
        if value not in VALID_SUBJECT_VALUES:
            raise UserDBValueError("Unknown 'subject' value: {!r}".format(value))
        self._data['subject'] = value

    # -----------------------------------------------------------------
    @property
    def language(self):
        """
        Get the user's preferred language ('sv', 'en', ...).

        :rtype: str | unicode
        """
        return self._data.get('preferredLanguage')

    @language.setter
    def language(self, value):
        """
        Set the user's preferred language.

        :param value: the language preference to set ('sv', 'en', ...)
        :type  value: str | unicode
        """
        self._data['preferredLanguage'] = value

    # -----------------------------------------------------------------
    @property
    def mail_addresses(self):
        """
        Get the user's email addresses.
        :return: MailAddressList object
        :rtype: eduid_userdb.mail.MailAddressList
        """
        # no setter for this one, as the MailAddressList object provides modification functions
        return self._mail_addresses

    # -----------------------------------------------------------------
    @property
    def phone_numbers(self):
        """
        Get the user's phone numbers.
        :return: PhoneNumberList object
        :rtype: eduid_userdb.phone.PhoneNumberList
        """
        # no setter for this one, as the PhoneNumberList object provides modification functions
        return self._phone_numbers

    # -----------------------------------------------------------------
    @property
    def passwords(self):
        """
        Get the user's phone numbers.
        :return: PasswordList object
        :rtype: eduid_userdb.password.PasswordList
        """
        # no setter for this one, as the PasswordList object provides modification functions
        return self._passwords

    # -----------------------------------------------------------------
    @property
    def nins(self):
        """
        Get the user's national identity numbers.
        :return: NinList object
        :rtype: eduid_userdb.nin.NinList
        """
        # no setter for this one, as the NinList object provides modification functions
        return self._nins

    # -----------------------------------------------------------------
    @property
    def modified_ts(self):
        """
        :return: Timestamp of last modification in the database.
                 None if User has never been written to the database.
        :rtype: datetime.datetime | None
        """
        return self._data.get('modified_ts')

    @modified_ts.setter
    def modified_ts(self, value):
        """
        :param value: Timestamp of modification.
                      Value None is ignored, True is short for datetime.utcnow().
        :type value: datetime.datetime | True | None
        """
        if value is None:
            return
        if value is True:
            value = datetime.datetime.utcnow()
        self._data['modified_ts'] = value

    # -----------------------------------------------------------------
    @property
    def entitlements(self):
        """
        :return: List of entitlements for this user.
        :rtype: [str | unicode]
        """
        return self._data.get('entitlements')

    @entitlements.setter
    def entitlements(self, value):
        """
        :param value: List of entitlements (strings).
        :type value: [str | unicode]
        """
        if value is None:
            return
        if not isinstance(value, list):
            raise UserDBValueError("Unknown 'entitlements' value: {!r}".format(value))
        for this in value:
            if not isinstance(this, basestring):
                raise UserDBValueError("Unknown 'entitlements' element: {!r}".format(this))
        self._data['entitlements'] = value

    # -----------------------------------------------------------------
    def to_dict(self, old_userdb_format=False):
        """
        Return user data serialized into a dict that can be stored in MongoDB.

        :param old_userdb_format: Set to True to get the dict in the old database format.
        :type old_userdb_format: bool

        :return: User as dict
        :rtype: dict
        """
        res = copy.copy(self._data)  # avoid caller messing up our private _data
        res['mailAliases'] = self.mail_addresses.to_list_of_dicts(old_userdb_format=old_userdb_format)
        res['phone'] = self.phone_numbers.to_list_of_dicts(old_userdb_format=old_userdb_format)
        res['passwords'] = self.passwords.to_list_of_dicts(old_userdb_format=old_userdb_format)
        res['nins'] = self.nins.to_list_of_dicts(old_userdb_format=old_userdb_format)
        if old_userdb_format:
            if 'surname' in res:
                res['sn'] = res.pop('surname')
            res['mail'] = self.mail_addresses.primary.email
            if 'phone' in res:
                res['mobile'] = res.pop('phone')
            if 'entitlements' in res:
                res['eduPersonEntitlement'] = res.pop('entitlements')
            if 'nins' in res:
                # Extract all verified NINs and return as a list of strings
                _nins = res.pop('nins')
                verified_nins = [this['number'] for this in _nins if this['verified']]
                res['norEduPersonNIN'] = verified_nins
        return res
