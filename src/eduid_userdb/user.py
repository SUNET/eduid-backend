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

from eduid_userdb.exceptions import UserHasUnknownData, UserIsRevoked, UserHasNotCompletedSignup
from eduid_userdb.element import UserDBValueError

from eduid_userdb.mail import MailAddressList
from eduid_userdb.phone import PhoneNumberList
from eduid_userdb.password import PasswordList
from eduid_userdb.nin import NinList
from eduid_userdb.tou import ToUList

VALID_SUBJECT_VALUES = ['physical person']


class User(object):
    """
    Generic eduID user object.

    :param data: MongoDB document representing a user
    :type  data: dict
    """
    def __init__(self, data, raise_on_unknown = True):
        self._data_in = copy.deepcopy(data)  # to not modify callers data
        self._data = dict()

        self._parse_check_invalid_users()

        # things without setters
        _id = self._data_in.pop('_id', None)
        if _id is None:
            _id = bson.ObjectId()
        if not isinstance(_id, bson.ObjectId):
            _id = bson.ObjectId(_id)
        self._data['_id'] = _id

        if 'sn' in self._data_in:
            self._data_in['surname'] = self._data_in.pop('sn')
        if 'eduPersonEntitlement' in self._data_in:
            self._data_in['entitlements'] = self._data_in.pop('eduPersonEntitlement')

        self._parse_mail_addresses()
        self._parse_phone_numbers()
        self._parse_nins()
        self._parse_tous()

        self._passwords = PasswordList(self._data_in.pop('passwords', []))
        # generic (known) attributes
        self.eppn = self._data_in.pop('eduPersonPrincipalName')  # mandatory
        self.subject = self._data_in.pop('subject', None)
        self.display_name = self._data_in.pop('displayName', None)
        self.given_name = self._data_in.pop('givenName', None)
        self.surname = self._data_in.pop('surname', None)
        self.language = self._data_in.pop('preferredLanguage', None)
        self.modified_ts = self._data_in.pop('modified_ts', None)
        self.entitlements = self._data_in.pop('entitlements', None)
        # obsolete attributes
        if 'postalAddress' in self._data_in:
            del self._data_in['postalAddress']
        if 'date' in self._data_in:
            del self._data_in['date']
        # temporary data we just want to retain as is
        for copy_attribute in ['letter_proofing_data']:
            if copy_attribute in self._data_in:
                self._data[copy_attribute] = self._data_in.pop(copy_attribute)

        if len(self._data_in) > 0:
            if raise_on_unknown:
                raise UserHasUnknownData('User {!s}/{!s} unknown data: {!r}'.format(
                    self.user_id, self.eppn, self._data_in.keys()
                ))
            # Just keep everything that is left as-is
            self._data.update(self._data_in)

    def __repr__(self):
        return '<eduID {!s}: {!s}/{!s}>'.format(self.__class__.__name__,
                                                self.eppn,
                                                self.user_id,
                                                )

    def __eq__(self, other):
        if self.__class__ is not other.__class__:
            raise TypeError('Trying to compare objects of different class')
        return self._data == other._data

    def _parse_check_invalid_users(self):
        """
        Part of __init__().

        Check users that can't be loaded for some known reason.
        """
        if 'revoked_ts' in self._data_in:
            raise UserIsRevoked('User {!s}/{!s} was revoked at {!s}'.format(
                self._data_in.get('_id'), self._data_in.get('eduPersonPrincipalName'), self._data_in['revoked_ts']))
        if 'passwords' not in self._data_in:
            raise UserHasNotCompletedSignup('User {!s}/{!s} is incomplete'.format(
                self._data_in.get('_id'), self._data_in.get('eduPersonPrincipalName')))

    def _parse_mail_addresses(self):
        """
        Part of __init__().

        Parse all the different formats of mail+mailAliases attributes in the database.
        """
        _mail_addresses = self._data_in.pop('mailAliases', [])
        if 'mail' in self._data_in:
            # old-style userdb primary e-mail address indicator
            for idx in xrange(len(_mail_addresses)):
                if _mail_addresses[idx]['email'] == self._data_in['mail']:
                    if 'passwords' in self._data_in:
                        # Work around a bug where one could signup, not follow the link in the e-mail
                        # and then do a password request to set a password. The e-mail address is
                        # implicitly verified by the password reset (which must have been done using e-mail).
                        _mail_addresses[idx]['verified'] = True
                    if 'verified' in _mail_addresses[idx] and _mail_addresses[idx]['verified']:
                        _mail_addresses[idx]['primary'] = True
            self._data_in.pop('mail')

        if len(_mail_addresses) == 1 and 'verified' in _mail_addresses[0] and _mail_addresses[0]['verified']:
            if 'primary' not in _mail_addresses[0] or \
                    _mail_addresses[0]['primary'] is False:
                # A single mail address was not set as Primary until it was verified
                _mail_addresses[0]['primary'] = True

        self._mail_addresses = MailAddressList(_mail_addresses)

    def _parse_phone_numbers(self):
        """
        Part of __init__().

        Parse all the different formats of mobile/phone attributes in the database.
        """
        if 'mobile' in self._data_in:
            _phones = self._data_in.pop('mobile')
            _primary = [x for x in _phones if x.get('primary', False)]
            if _phones and not _primary:
                # None of the phone numbers are primary. Promote the first verified
                # entry found.
                _primary_set = False
                for _this in _phones:
                    if _this.get('verified', False):
                        _this['primary'] = True
                        _primary_set = True
                        break
            self._data_in['phone'] = _phones

        _phones = self._data_in.pop('phone', [])
        self._phone_numbers = PhoneNumberList(_phones)

    def _parse_nins(self):
        """
        Part of __init__().

        Parse all the different formats of norEduPersonNIN attributes in the database.
        """
        _nins = self._data_in.pop('nins', [])
        if 'norEduPersonNIN' in self._data_in:
            # old-style list of verified nins
            old_nins = self._data_in.pop('norEduPersonNIN')
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
        self._nins = NinList(_nins)

    def _parse_tous(self):
        """
        Part of __init__().

        Parse the ToU acceptance events.
        """
        _tou = self._data_in.pop('tou', [])
        self._tou = ToUList(_tou)

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
    @property
    def tou(self):
        """
        Get the user's Terms of Use info.

        :return: ToUList object
        :rtype: eduid_userdb.nin.ToUList
        """
        # no setter for this one, as the ToUList object provides modification functions
        return self._tou

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
        res['tou'] = self.tou.to_list_of_dicts(old_userdb_format=old_userdb_format)
        if 'eduPersonEntitlement' not in res:
            res['eduPersonEntitlement'] = res.pop('entitlements', [])
        # Remove these values if they have a value that evaluates to False
        for _remove in ['displayName', 'givenName', 'surname', 'preferredLanguage', 'phone']:
            if _remove in res and not res[_remove]:
                del res[_remove]
        if old_userdb_format:
            if 'surname' in res:
                res['sn'] = res.pop('surname')
            _primary = self.mail_addresses.primary
            if _primary:
                res['mail'] = _primary.email
            if 'phone' in res:
                res['mobile'] = res.pop('phone')
            if 'nins' in res:
                # Extract all verified NINs and return as a list of strings
                _nins = res.pop('nins')
                verified_nins = [this['number'] for this in _nins if this['verified']]
                # don't even put 'norEduPersonNIN' in res if it is empty
                if verified_nins:
                    res['norEduPersonNIN'] = verified_nins
                elif 'norEduPersonNIN' in res:
                    del res['norEduPersonNIN']
            if res.get('mailAliases') == []:
                del res['mailAliases']
        return res
