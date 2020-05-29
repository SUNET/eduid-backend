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
import datetime
import warnings
from typing import Any, Dict, List, Optional, Type, TypeVar, Union

import bson

from eduid_userdb.credentials import CredentialList
from eduid_userdb.element import UserDBValueError
from eduid_userdb.exceptions import UserHasNotCompletedSignup, UserHasUnknownData, UserIsRevoked, UserMissingData
from eduid_userdb.locked_identity import LockedIdentityList
from eduid_userdb.mail import MailAddressList
from eduid_userdb.nin import NinList
from eduid_userdb.orcid import Orcid
from eduid_userdb.phone import PhoneNumberList
from eduid_userdb.profile import ProfileList
from eduid_userdb.tou import ToUList

VALID_SUBJECT_VALUES = ['physical person']

U = TypeVar('U', bound='User')


class User(object):
    """
    Generic eduID user object.

    :param data: MongoDB document representing a user
    :type  data: dict
    """

    def __init__(self, data: Dict[str, Any], raise_on_unknown: bool = True, called_directly: bool = True):
        if called_directly:
            warnings.warn("User.__init__ called directly", DeprecationWarning)

        self._data_in = copy.deepcopy(data)  # to not modify callers data
        self._data_orig = copy.deepcopy(data)  # to not modify callers data
        self._data: Dict[str, Any] = dict()

        self.check_or_use_data()

        self._parse_check_invalid_users()

        # things without setters
        _id = self._data_in.pop('_id', None)
        if _id is None:
            _id = bson.ObjectId()
        if not isinstance(_id, bson.ObjectId):
            _id = bson.ObjectId(_id)
        self._data['_id'] = _id

        if 'sn' in self._data_in:
            _sn = self._data_in.pop('sn')
            # Some users have both 'sn' and 'surname'. In that case, assume sn was
            # once converted to surname but also left behind, and discard 'sn'.
            if 'surname' not in self._data_in:
                self._data_in['surname'] = _sn
        if 'eduPersonEntitlement' in self._data_in:
            self._data_in['entitlements'] = self._data_in.pop('eduPersonEntitlement')

        self._parse_mail_addresses()
        self._parse_phone_numbers()
        self._parse_nins()
        self._parse_tous()
        self._parse_locked_identity()
        self._parse_orcid()
        self._parse_profiles()

        self._credentials = CredentialList(self._data_in.pop('passwords', []))
        # generic (known) attributes
        self.eppn = self._data_in.pop('eduPersonPrincipalName')  # mandatory
        self.subject = self._data_in.pop('subject', None)
        self.display_name = self._data_in.pop('displayName', None)
        self.given_name = self._data_in.pop('givenName', None)
        self.surname = self._data_in.pop('surname', None)
        self.language = self._data_in.pop('preferredLanguage', None)
        self.modified_ts = self._data_in.pop('modified_ts', None)
        self.entitlements = self._data_in.pop('entitlements', None)
        self.terminated = self._data_in.pop('terminated', None)
        # obsolete attributes
        if 'postalAddress' in self._data_in:
            del self._data_in['postalAddress']
        if 'date' in self._data_in:
            del self._data_in['date']
        if 'csrf' in self._data_in:
            del self._data_in['csrf']
        # temporary data we just want to retain as is
        for copy_attribute in ['letter_proofing_data']:
            if copy_attribute in self._data_in:
                self._data[copy_attribute] = self._data_in.pop(copy_attribute)

        if len(self._data_in) > 0:
            if raise_on_unknown:
                raise UserHasUnknownData(
                    'User {!s}/{!s} unknown data: {!r}'.format(self.user_id, self.eppn, self._data_in.keys())
                )
            # Just keep everything that is left as-is
            self._data.update(self._data_in)

    @classmethod
    def construct_user(
        cls: Type[U],
        eppn: Optional[str] = None,
        _id: Optional[Union[bson.ObjectId, str]] = None,
        subject: Optional[str] = None,
        display_name: Optional[str] = None,
        given_name: Optional[str] = None,
        surname: Optional[str] = None,
        language: Optional[str] = None,
        passwords: Optional[CredentialList] = None,
        modified_ts: Optional[datetime.datetime] = None,
        revoked_ts: Optional[datetime.datetime] = None,
        entitlements: Optional[List[str]] = None,
        terminated: Optional[bool] = None,
        letter_proofing_data: Optional[dict] = None,
        mail_addresses: Optional[MailAddressList] = None,
        phone_numbers: Optional[PhoneNumberList] = None,
        nins: Optional[NinList] = None,
        tou: Optional[ToUList] = None,
        locked_identity: Optional[LockedIdentityList] = None,
        orcid: Optional[Orcid] = None,
        profiles: Optional[ProfileList] = None,
        raise_on_unknown: bool = True,
        **kwargs,
    ) -> U:
        """
        Construct user from data in typed params.
        """

        data: Dict[str, Any] = {}

        data['_id'] = _id
        if eppn is None:
            raise UserMissingData("User objects must be constructed with an eppn")
        data['eduPersonPrincipalName'] = eppn
        data['subject'] = subject
        data['displayName'] = display_name
        data['givenName'] = given_name
        data['surname'] = surname
        data['preferredLanguage'] = language
        data['modified_ts'] = modified_ts
        data['terminated'] = terminated
        if revoked_ts is not None:
            data['revoked_ts'] = revoked_ts
        if orcid is not None:
            data['orcid'] = orcid.to_dict()
        if letter_proofing_data is not None:
            data['letter_proofing_data'] = letter_proofing_data
        if passwords is not None:
            data['passwords'] = passwords.to_list_of_dicts()
        if entitlements is not None:
            data['entitlements'] = entitlements
        if mail_addresses is not None:
            data['mailAliases'] = mail_addresses.to_list_of_dicts()
        if phone_numbers is not None:
            data['phone'] = phone_numbers.to_list_of_dicts()
        if nins is not None:
            data['nins'] = nins.to_list_of_dicts()
        if tou is not None:
            data['tou'] = tou.to_list_of_dicts()
        if locked_identity is not None:
            data['locked_identity'] = locked_identity.to_list_of_dicts()
        if profiles is not None:
            data['profiles'] = profiles.to_list_of_dicts()

        data.update(kwargs)

        return cls.from_dict(data)

    def check_or_use_data(self):
        """
        Derived classes can override this method to check that the provided data
        is enough for their purposes, or to deal specially with particular bits of it.

        In case of problems they sould raise whatever Exception is appropriate.
        """
        pass

    @classmethod
    def from_dict(cls: Type[U], data: Dict[str, Any], raise_on_unknown: bool = True) -> U:
        """
        Construct user from a data dict.
        """
        return cls(data=data, raise_on_unknown=raise_on_unknown, called_directly=False)

    def __repr__(self):
        return '<eduID {!s}: {!s}/{!s}>'.format(self.__class__.__name__, self.eppn, self.user_id,)

    def __eq__(self, other):
        if self.__class__ is not other.__class__:
            raise TypeError(
                'Trying to compare objects of different class {!r} - {!r} '.format(self.__class__, other.__class__)
            )
        return self._data == other._data

    def _parse_check_invalid_users(self):
        """
        Part of __init__().

        Check users that can't be loaded for some known reason.
        """
        if 'revoked_ts' in self._data_in:
            raise UserIsRevoked(
                'User {!s}/{!s} was revoked at {!s}'.format(
                    self._data_in.get('_id'), self._data_in.get('eduPersonPrincipalName'), self._data_in['revoked_ts']
                )
            )
        if 'passwords' not in self._data_in:
            raise UserHasNotCompletedSignup(
                'User {!s}/{!s} is incomplete'.format(
                    self._data_in.get('_id'), self._data_in.get('eduPersonPrincipalName')
                )
            )

    def _parse_mail_addresses(self):
        """
        Part of __init__().

        Parse all the different formats of mail+mailAliases attributes in the database.
        """
        _mail_addresses = self._data_in.pop('mailAliases', [])
        if 'mail' in self._data_in:
            # old-style userdb primary e-mail address indicator
            for idx in range(len(_mail_addresses)):
                if _mail_addresses[idx]['email'] == self._data_in['mail']:
                    if 'passwords' in self._data_in:
                        # Work around a bug where one could signup, not follow the link in the e-mail
                        # and then do a password reset to set a password. The e-mail address is
                        # implicitly verified by the password reset (which must have been done using e-mail).
                        _mail_addresses[idx]['verified'] = True
                    # If a user does not already have a primary mail address promote "mail" to primary if
                    # it is verified
                    _has_primary = any([item.get('primary', False) for item in _mail_addresses])
                    if _mail_addresses[idx].get('verified', False) and not _has_primary:
                        _mail_addresses[idx]['primary'] = True
            self._data_in.pop('mail')

        if len(_mail_addresses) == 1 and _mail_addresses[0].get('verified', False):
            if not _mail_addresses[0].get('primary', False):
                # A single mail address was not set as Primary until it was verified
                _mail_addresses[0]['primary'] = True

        self._mail_addresses = MailAddressList(_mail_addresses)

    def _parse_phone_numbers(self):
        """
        Part of __init__().

        Parse all the different formats of mobile/phone attributes in the database.
        """
        if 'mobile' in self._data_in:
            _mobile = self._data_in.pop('mobile')
            if 'phone' not in self._data_in:
                # Some users have both 'mobile' and 'phone'. Assume mobile was once transformed
                # to 'phone' but also left behind - so just discard 'mobile'.
                self._data_in['phone'] = _mobile
        if 'phone' in self._data_in:
            _phones = self._data_in.pop('phone')
            # Clean up for non verified phone elements that where still primary
            for _this in _phones:
                if not _this.get('verified', False) and _this.get('primary', False):
                    _this['primary'] = False
            _primary = [x for x in _phones if x.get('primary', False)]
            if _phones and not _primary:
                # None of the phone numbers are primary. Promote the first verified
                # entry found (or none if there are no verified entries).
                for _this in _phones:
                    if _this.get('verified', False):
                        _this['primary'] = True
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
                if isinstance(this, str):
                    # XXX lookup NIN in eduid-dashboards verifications to make sure it is verified somehow?
                    _primary = not _nins
                    _nins.append(
                        {'number': this, 'primary': _primary, 'verified': True,}
                    )
                elif isinstance(this, dict):
                    _nins.append(
                        {
                            'number': this.pop('number'),
                            'primary': this.pop('primary'),
                            'verified': this.pop('verified'),
                        }
                    )
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

    def _parse_locked_identity(self):
        """
        Part of __init__().

        Parse the LockedIdentity elements.
        """
        _locked_identity = self._data_in.pop('locked_identity', [])
        self._locked_identity = LockedIdentityList(_locked_identity)

    def _parse_orcid(self):
        """
        Part of __init__().

        Parse the Orcid element.
        """
        self._orcid = None
        _orcid = self._data_in.pop('orcid', None)
        if _orcid is not None:
            self._orcid = Orcid(data=_orcid)

    def _parse_profiles(self):
        """
        Part of __init__().

        Parse the Profile elements.
        """
        _profiles = self._data_in.pop('profiles', [])
        self._profiles = ProfileList.from_list_of_dicts(_profiles)

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
    def credentials(self):
        """
        Get the user's credentials.
        :return: CredentialList object
        :rtype: eduid_userdb.credentials.CredentialList
        """
        # no setter for this one, as the CredentialList object provides modification functions
        return self._credentials

    @property
    def passwords(self):
        """
        DEPRECATED - see credentials.
        :return: CredentialList object
        :rtype: eduid_userdb.credentials.CredentialList
        """
        # no setter for this one, as the CredentialList object provides modification functions
        return self._credentials

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
            if not isinstance(this, str):
                raise UserDBValueError("Unknown 'entitlements' element: {!r}".format(this))
        self._data['entitlements'] = value

    # -----------------------------------------------------------------
    @property
    def tou(self):
        """
        Get the user's Terms of Use info.

        :return: ToUList object
        :rtype: eduid_userdb.tou.ToUList
        """
        # no setter for this one, as the ToUList object provides modification functions
        return self._tou

    # -----------------------------------------------------------------
    @property
    def terminated(self):
        """
        Get the user's terminated status (False or the timestamp when the user was terminated).

        :rtype: False | datetime
        """
        return self._data.get('terminated', False)

    @terminated.setter
    def terminated(self, value):
        """
        :param value: Set the user's terminated status.
        :type value: bool
        """
        if value is not None:
            if not isinstance(value, bool) and not isinstance(value, datetime.datetime):
                raise UserDBValueError('Non-bool/datetime terminated value')
            if value is True:
                value = datetime.datetime.utcnow()
            self._data['terminated'] = value

    # -----------------------------------------------------------------
    @property
    def locked_identity(self):
        """
        :return: Identity locked to this user or empty list
        :rtype: LockedIdentityList
        """
        return self._locked_identity

    # -----------------------------------------------------------------
    @property
    def orcid(self):
        """
        :return: Users ORCID
        :rtype: Orcid | None
        """
        return self._orcid

    @orcid.setter
    def orcid(self, value):
        """
        :param value: Users ORCID
        :type value: Orcid

        :return: Users ORCID
        :rtype: Orcid | None
        """
        if value is None or isinstance(value, Orcid):
            self._orcid = value
        else:
            raise UserDBValueError("Unknown 'orcid' value: {!r}".format(value))

    # -----------------------------------------------------------------
    @property
    def profiles(self) -> ProfileList:
        """
        :return: Profiles for this user or empty list
        """
        return self._profiles

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
        res['passwords'] = self.credentials.to_list_of_dicts(old_userdb_format=old_userdb_format)
        res['nins'] = self.nins.to_list_of_dicts(old_userdb_format=old_userdb_format)
        res['tou'] = self.tou.to_list_of_dicts()
        res['locked_identity'] = self.locked_identity.to_list_of_dicts(old_userdb_format=old_userdb_format)
        res['orcid'] = None
        if self.orcid is not None:
            res['orcid'] = self.orcid.to_dict()
        if 'eduPersonEntitlement' not in res:
            res['eduPersonEntitlement'] = res.pop('entitlements', [])
        # Remove these values if they have a value that evaluates to False
        for _remove in [
            'displayName',
            'givenName',
            'surname',
            'preferredLanguage',
            'phone',
            'orcid',
            'eduPersonEntitlement',
            'locked_identity',
            'nins',
        ]:
            if _remove in res and not res[_remove]:
                del res[_remove]
        if old_userdb_format:
            _primary = self.mail_addresses.primary
            if _primary:
                res['mail'] = _primary.email
            if 'phone' in res:
                res['mobile'] = res.pop('phone')
            if 'surname' in res:
                res['sn'] = res.pop('surname')
            if 'nins' in res:
                # Extract all verified NINs and return as a list of strings
                _nins = res.pop('nins')
                verified_nins = [this['number'] for this in _nins if this['verified']]
                # don't even put 'norEduPersonNIN' in res if it is empty
                if verified_nins:
                    res['norEduPersonNIN'] = verified_nins
                elif 'norEduPersonNIN' in res:
                    del res['norEduPersonNIN']
            if res.get('mailAliases') is list():
                del res['mailAliases']
        return res

    # -----------------------------------------------------------------
    @classmethod
    def from_user(cls, user, private_userdb):
        """
        This function is only expected to be used by subclasses of User.

        :param user: User instance from AM database
        :param private_userdb: Private UserDB to load modified_ts from

        :type user: User
        :type private_userdb: eduid_userdb.UserDB

        :return: User proper
        :rtype: cls
        """
        user_dict = user.to_dict()
        private_user = private_userdb.get_user_by_eppn(user.eppn, raise_on_missing=False)
        if private_user is None:
            user_dict.pop('modified_ts', None)
        else:
            user_dict['modified_ts'] = private_user.modified_ts
        return cls(data=user_dict)
