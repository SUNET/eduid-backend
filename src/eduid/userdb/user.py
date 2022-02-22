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
from __future__ import annotations

import copy
from datetime import datetime
from enum import Enum, unique
from typing import Any, Dict, List, Mapping, Optional, Type, TypeVar, cast

import bson
from pydantic import BaseModel, Extra, Field, root_validator, validator

from eduid.userdb.credentials import CredentialList
from eduid.userdb.db import BaseDB
from eduid.userdb.element import UserDBValueError
from eduid.userdb.exceptions import UserHasNotCompletedSignup, UserIsRevoked
from eduid.userdb.ladok import Ladok
from eduid.userdb.locked_identity import LockedIdentityList
from eduid.userdb.mail import MailAddressList
from eduid.userdb.nin import NinList
from eduid.userdb.orcid import Orcid
from eduid.userdb.phone import PhoneNumberList
from eduid.userdb.profile import ProfileList
from eduid.userdb.tou import ToUList

TUserSubclass = TypeVar('TUserSubclass', bound='User')


@unique
class SubjectType(str, Enum):
    PERSON = 'physical person'


class User(BaseModel):
    """
    Generic eduID user object.
    """

    eppn: str = Field(alias='eduPersonPrincipalName')
    user_id: bson.ObjectId = Field(default_factory=bson.ObjectId, alias='_id')
    given_name: str = Field(default='', alias='givenName')
    display_name: Optional[str] = Field(default=None, alias='displayName')
    surname: str = ''
    subject: Optional[SubjectType] = None
    language: str = Field(default='sv', alias='preferredLanguage')
    mail_addresses: MailAddressList = Field(default_factory=MailAddressList, alias='mailAliases')
    phone_numbers: PhoneNumberList = Field(default_factory=PhoneNumberList, alias='phone')
    credentials: CredentialList = Field(default_factory=CredentialList, alias='passwords')
    nins: NinList = Field(default_factory=NinList)
    modified_ts: Optional[datetime] = None
    entitlements: List[str] = Field(default_factory=list, alias='eduPersonEntitlement')
    tou: ToUList = Field(default_factory=ToUList)
    terminated: Optional[datetime] = None
    locked_identity: LockedIdentityList = Field(default_factory=LockedIdentityList)
    orcid: Optional[Orcid] = None
    ladok: Optional[Ladok] = None
    profiles: ProfileList = Field(default_factory=ProfileList)
    letter_proofing_data: Optional[list] = None
    revoked_ts: Optional[datetime] = None

    class Config:
        allow_population_by_field_name = True  # allow setting created_ts by name, not just it's alias
        validate_assignment = True  # validate data when updated, not just when initialised
        extra = Extra.forbid  # reject unknown data
        arbitrary_types_allowed = True  # allow ObjectId as type in Event

    @validator('eppn', pre=True)
    def check_eppn(cls, v: str) -> str:
        # TODO: what about the comment below?
        # safe-guard against User being instantiated with a dict, instead of the dict
        # being passed to User.from_dict().
        if not isinstance(v, str):
            raise UserDBValueError('User instantiated with non-string eppn')

        if len(v) != 11 or '-' not in v:
            # the exception to the rule - an old proquint implementation once generated a short eppn
            if v != 'holih':
                # have to provide an exception for test cases for now ;)
                if not v.startswith('hubba-') and 'test' not in v:
                    raise UserDBValueError(f'Malformed eppn ({v})')
        return v

    @root_validator(pre=True)
    def check_revoked(cls, values: Dict[str, Any]):
        # raise exception if the user is revoked
        if values.get('revoked_ts') is not None:
            raise UserIsRevoked(
                f'User {values.get("user_id")}/{values.get("eppn")} was revoked at {values.get("revoked_ts")}'
            )
        return values

    def __str__(self):
        return f'<eduID {self.__class__.__name__}: {self.eppn}/{self.user_id}>'

    def __eq__(self, other):
        if self.__class__ is not other.__class__:
            raise TypeError(f'Trying to compare objects of different class {other.__class__} != {self.__class__}')
        return self.to_dict() == other.to_dict()

    @classmethod
    def from_dict(cls: Type[TUserSubclass], data: Mapping[str, Any]) -> TUserSubclass:
        """
        Construct user from a data dict.
        """
        data_in = dict(copy.deepcopy(data))  # to not modify callers data

        data_in = cls.check_or_use_data(data_in)
        data_in = cls._from_dict_transform(data_in)
        return cls(**data_in)

    def to_dict(self) -> Dict[str, Any]:
        """
        Return user data serialized into a dict that can be stored in MongoDB.

        :return: User as dict
        """
        res = self.dict(by_alias=True, exclude_none=True)  # avoid caller messing up our private _data
        res = self._to_dict_transform(res)
        return res

    @classmethod
    def _from_dict_transform(cls: Type[TUserSubclass], data: Dict[str, Any]) -> Dict[str, Any]:
        # clean up sn
        if 'sn' in data:
            _sn = data.pop('sn')
            # Some users have both 'sn' and 'surname'. In that case, assume sn was
            # once converted to surname but also left behind, and discard 'sn'.
            if 'surname' not in data:
                data['surname'] = _sn

        # parse complex data
        data['mail_addresses'] = cls._parse_mail_addresses(data)
        data['phone_numbers'] = cls._parse_phone_numbers(data)
        data['nins'] = cls._parse_nins(data)
        data['tou'] = cls._parse_tous(data)
        data['locked_identity'] = cls._parse_locked_identity(data)
        data['orcid'] = cls._parse_orcid(data)
        data['ladok'] = cls._parse_ladok(data)
        data['profiles'] = cls._parse_profiles(data)
        data['credentials'] = CredentialList.from_list_of_dicts(data.pop('passwords', []))
        if data.get('subject') is not None:
            data['subject'] = SubjectType(data['subject'])

        return data

    def _to_dict_transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # serialize complex data
        data['mailAliases'] = self.mail_addresses.to_list_of_dicts()
        data['phone'] = self.phone_numbers.to_list_of_dicts()
        data['passwords'] = self.credentials.to_list_of_dicts()
        data['nins'] = self.nins.to_list_of_dicts()
        if self.tou is not None:
            data['tou'] = self.tou.to_list_of_dicts()
        data['locked_identity'] = self.locked_identity.to_list_of_dicts()
        data['profiles'] = self.profiles.to_list_of_dicts()
        data['orcid'] = None
        if self.orcid is not None:
            data['orcid'] = self.orcid.to_dict()
        if self.ladok is not None:
            data['ladok'] = self.ladok.to_dict()
        return data

    @classmethod
    def from_user(cls: Type[TUserSubclass], user: User, private_userdb: BaseDB) -> TUserSubclass:
        """
        This function is only expected to be used by subclasses of User.

        :param user: User instance from AM database
        :param private_userdb: Private UserDB to load modified_ts from

        :return: User proper
        """
        # We cast here to avoid importing UserDB at the module level thus creating a circular import
        from eduid.userdb import UserDB

        private_userdb = cast(UserDB, private_userdb)

        user_dict = user.to_dict()
        private_user = private_userdb.get_user_by_eppn(user.eppn)
        if private_user is None:
            user_dict.pop('modified_ts', None)
        else:
            user_dict['modified_ts'] = private_user.modified_ts
        return cls.from_dict(data=user_dict)

    @classmethod
    def check_or_use_data(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Derived classes can override this method to check that the provided data
        is enough for their purposes, or to deal specially with particular bits of it.

        In case of problems they should raise whatever Exception is appropriate.
        """
        if 'passwords' not in data:
            raise UserHasNotCompletedSignup(
                'User {!s}/{!s} is incomplete'.format(data.get('_id'), data.get('eduPersonPrincipalName'))
            )
        return data

    @classmethod
    def _parse_mail_addresses(cls, data: Dict[str, Any]) -> MailAddressList:
        """
        Part of __init__().

        Parse all the different formats of mail+mailAliases attributes in the database.
        """
        _mail_addresses = data.pop('mailAliases', [])
        if 'mail' in data:
            # old-style userdb primary e-mail address indicator
            for idx in range(len(_mail_addresses)):
                if _mail_addresses[idx]['email'] == data['mail']:
                    if 'passwords' in data:
                        # Work around a bug where one could signup, not follow the link in the e-mail
                        # and then do a password reset to set a password. The e-mail address is
                        # implicitly verified by the password reset (which must have been done using e-mail).
                        _mail_addresses[idx]['verified'] = True
                    # If a user does not already have a primary mail address promote "mail" to primary if
                    # it is verified
                    _has_primary = any([item.get('primary', False) for item in _mail_addresses])
                    if _mail_addresses[idx].get('verified', False) and not _has_primary:
                        _mail_addresses[idx]['primary'] = True
            data.pop('mail')

        if (
            isinstance(_mail_addresses, list)
            and len(_mail_addresses) == 1
            and _mail_addresses[0].get('verified', False)
        ):
            if not _mail_addresses[0].get('primary', False):
                # A single mail address was not set as Primary until it was verified
                _mail_addresses[0]['primary'] = True

        return MailAddressList.from_list_of_dicts(_mail_addresses)

    @classmethod
    def _parse_phone_numbers(cls, data: Dict[str, Any]) -> PhoneNumberList:
        """
        Parse all the different formats of mobile/phone attributes in the database.
        """
        if 'mobile' in data:
            _mobile = data.pop('mobile')
            if 'phone' not in data:
                # Some users have both 'mobile' and 'phone'. Assume mobile was once transformed
                # to 'phone' but also left behind - so just discard 'mobile'.
                data['phone'] = _mobile
        if 'phone' in data:
            _phones = data.pop('phone')
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
            data['phone'] = _phones

        _phones = data.pop('phone', [])

        return PhoneNumberList.from_list_of_dicts(_phones)

    @classmethod
    def _parse_nins(cls, data: Dict[str, Any]) -> NinList:
        """
        Parse all the different formats of norEduPersonNIN attributes in the database.
        """
        _nins = data.pop('nins', [])
        if 'norEduPersonNIN' in data:
            # old-style list of verified nins
            old_nins = data.pop('norEduPersonNIN')
            for this in old_nins:
                if isinstance(this, str):
                    # XXX lookup NIN in eduid-dashboards verifications to make sure it is verified somehow?
                    _primary = not _nins
                    _nins.append({'number': this, 'primary': _primary, 'verified': True})
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
        return NinList.from_list_of_dicts(_nins)

    @classmethod
    def _parse_tous(cls, data: Dict[str, Any]) -> ToUList:
        """
        Parse the ToU acceptance events.
        """
        _tou = data.pop('tou', [])
        return ToUList.from_list_of_dicts(_tou)

    @classmethod
    def _parse_locked_identity(cls, data: Dict[str, Any]) -> LockedIdentityList:
        """
        Parse the LockedIdentity elements.
        """
        _locked_identity = data.pop('locked_identity', [])
        return LockedIdentityList.from_list_of_dicts(_locked_identity)

    @classmethod
    def _parse_orcid(cls, data: Dict[str, Any]) -> Optional[Orcid]:
        """
        Parse the Orcid element.
        """
        orcid = data.pop('orcid', None)
        if orcid is not None:
            return Orcid.from_dict(orcid)
        return None

    @classmethod
    def _parse_ladok(cls, data: Dict[str, Any]) -> Optional[Ladok]:
        """
        Parse the Ladok element.
        """
        ladok = data.pop('ladok', None)
        if ladok is not None:
            # TODO: This try/except is to flush out old format of ladok data from development, remove soon!
            try:
                return Ladok.from_dict(ladok)
            except:
                return None
        return None

    @classmethod
    def _parse_profiles(cls, data: Dict[str, Any]) -> ProfileList:
        """
        Parse the Profile elements.
        """
        profiles = data.pop('profiles', [])
        if isinstance(profiles, list):
            return ProfileList.from_list_of_dicts(profiles)
        return profiles
