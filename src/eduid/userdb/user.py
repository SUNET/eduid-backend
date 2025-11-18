from __future__ import annotations

import copy
import logging
from datetime import datetime
from enum import StrEnum, unique
from operator import itemgetter
from typing import Any, Self, TypeVar, cast

import bson
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from eduid.userdb.credentials import CredentialList
from eduid.userdb.db import BaseDB, TUserDbDocument
from eduid.userdb.element import UserDBValueError
from eduid.userdb.exceptions import UserDoesNotExist, UserHasNotCompletedSignup, UserIsRevoked
from eduid.userdb.identity import EIDASIdentity, EIDASLoa, IdentityList, IdentityType
from eduid.userdb.ladok import Ladok
from eduid.userdb.locked_identity import LockedIdentityList
from eduid.userdb.mail import MailAddressList
from eduid.userdb.meta import Meta
from eduid.userdb.nin import NinList
from eduid.userdb.orcid import Orcid
from eduid.userdb.phone import PhoneNumberList
from eduid.userdb.profile import ProfileList
from eduid.userdb.tou import ToUList

logger = logging.getLogger(__name__)

TUserSubclass = TypeVar("TUserSubclass", bound="User")

EPPN_LENGTH = 11


@unique
class SubjectType(StrEnum):
    PERSON = "physical person"


class UserPreferences(BaseModel):
    always_use_security_key: bool = Field(default=True)


class User(BaseModel):
    """
    Generic eduID user object.
    """

    meta: Meta = Field(default_factory=Meta)
    eppn: str = Field(alias="eduPersonPrincipalName")
    user_id: bson.ObjectId = Field(default_factory=bson.ObjectId, alias="_id")
    given_name: str | None = Field(default=None, alias="givenName")
    chosen_given_name: str | None = None
    surname: str | None = None
    legal_name: str | None = None
    subject: SubjectType | None = None
    # TODO: Move language in to settings and set the initial value in signup flow based in browser language
    language: str | None = Field(default=None, alias="preferredLanguage")
    mail_addresses: MailAddressList = Field(default_factory=MailAddressList, alias="mailAliases")
    phone_numbers: PhoneNumberList = Field(default_factory=PhoneNumberList, alias="phone")
    credentials: CredentialList = Field(default_factory=CredentialList, alias="passwords")
    identities: IdentityList = Field(default_factory=IdentityList)
    modified_ts: datetime | None = None  # TODO: remove after meta.modified_ts is used
    entitlements: list[str] = Field(default_factory=list, alias="eduPersonEntitlement")
    tou: ToUList = Field(default_factory=ToUList)
    terminated: datetime | None = None
    locked_identity: LockedIdentityList = Field(default_factory=LockedIdentityList)
    orcid: Orcid | None = None
    ladok: Ladok | None = None
    profiles: ProfileList = Field(default_factory=ProfileList)
    letter_proofing_data: list | dict | None = None  # remove dict after a full load-save-users
    revoked_ts: datetime | None = None
    preferences: UserPreferences = Field(default_factory=UserPreferences)
    model_config = ConfigDict(
        populate_by_name=True, validate_assignment=True, extra="forbid", arbitrary_types_allowed=True
    )

    @property
    def friendly_identifier(self) -> str:
        """
        Should return something that the user can identify their account with.
        For now, it will be chosen given name + surname -> given name + surname -> eppn.
        """
        if self.chosen_given_name and self.surname:
            return f"{self.chosen_given_name} {self.surname}"
        elif self.given_name and self.surname:
            return f"{self.given_name} {self.surname}"
        return self.eppn

    @field_validator("eppn", mode="before")
    @classmethod
    def check_eppn(cls, v: str) -> str:
        if len(v) != EPPN_LENGTH or "-" not in v:
            # the exception to the rule - an old proquint implementation once generated a short eppn
            if v != "holih":
                # have to provide an exception for test cases for now ;)
                if not v.startswith("hubba-") and "test" not in v:
                    raise UserDBValueError(f"Malformed eppn ({v})")
        return v

    @model_validator(mode="before")
    @classmethod
    def check_revoked(cls, values: dict[str, Any]) -> dict[str, Any]:
        # raise exception if the user is revoked
        if values.get("revoked_ts") is not None:
            raise UserIsRevoked(
                f"User {values.get('user_id')}/{values.get('eppn')} was revoked at {values.get('revoked_ts')}"
            )
        return values

    @model_validator(mode="after")
    def update_meta_modified_ts(self) -> Self:
        # as we validate on assignment this will run every time the User is changed
        if self.modified_ts:
            self.meta.modified_ts = self.modified_ts
        return self

    def __str__(self) -> str:
        """
        Return a string representation of the user, suitable for logging.

        Includes the current version of the user in the database to signify that "this is version X of the user foo".

        Example: '<eduID User: hubba-bubba/v1234567890987654321>'
        """
        if self.meta.is_in_database:
            return f"<eduID {self.__class__.__name__}: {self.eppn}/v{self.meta.version}>"
        return f"<eduID {self.__class__.__name__}: {self.eppn}/not in db>"

    @classmethod
    def from_dict(cls: type[TUserSubclass], data: TUserDbDocument) -> TUserSubclass:
        """
        Construct user from a data dict.
        """
        data_in = dict(copy.deepcopy(data))  # to not modify callers data

        data_in = cls.check_or_use_data(data_in)
        data_in = cls._from_dict_transform(data_in)
        return cls(**data_in)

    def to_dict(self) -> TUserDbDocument:
        """
        Return user data serialized into a dict that can be stored in MongoDB.

        :return: User as dict
        """
        res = self.model_dump(by_alias=True, exclude_none=True)
        res = self._to_dict_transform(res)
        return TUserDbDocument(res)

    @classmethod
    def _from_dict_transform(cls: type[TUserSubclass], data: dict[str, Any]) -> dict[str, Any]:
        # clean up sn
        if "sn" in data:
            _sn = data.pop("sn")
            # Some users have both 'sn' and 'surname'. In that case, assume sn was
            # once converted to surname but also left behind, and discard 'sn'.
            if "surname" not in data:
                data["surname"] = _sn

        # clean up displayName
        if "displayName" in data:
            data.pop("displayName")

        # migrate nins to identities
        # TODO: Remove parsing of nins after next full load-save
        _nins = data.pop("nins", None)
        if _nins:  # check for None or empty list
            nin_list = NinList.from_list_of_dicts(_nins)
            if nin_list.count == 1:
                _nin = nin_list.to_list_of_dicts()[0]
            # somehow the user has more than one nin
            elif nin_list.primary is not None:
                # use primary if any
                _nin = nin_list.primary.to_dict()
            else:
                # else use the nin added first
                _nin = sorted(nin_list.to_list_of_dicts(), key=itemgetter("created_ts"))[0]
            _identities = data.pop("identities", [])
            existing_nin = [item for item in _identities if item.get("identity_type") == IdentityType.NIN.value]
            if not existing_nin:  # workaround for users that did not get their nins list removed due to a bug in am
                # Add identity type and remove primary key for old nin objects
                _nin["identity_type"] = IdentityType.NIN.value
                del _nin["primary"]
                _identities.append(_nin)
            data["identities"] = _identities

        # migrate LockedIdentity objects to IdentityElements
        # is_verified was not part of LockedIdentity objects
        # TODO: Remove after next full load-save
        for _locked_nin in data.get("locked_identity", []):
            _locked_nin["verified"] = True

        # users can have terminated set to False due to earlier bug
        # TODO: Remove after next full load-save
        if "terminated" in data and data["terminated"] is False:
            data["terminated"] = None

        # parse complex data
        data["mail_addresses"] = cls._parse_mail_addresses(data)
        data["phone_numbers"] = cls._parse_phone_numbers(data)
        data["identities"] = cls._parse_identities(data)
        data["tou"] = cls._parse_tous(data)
        data["locked_identity"] = cls._parse_locked_identity(data)
        data["orcid"] = cls._parse_orcid(data)
        data["ladok"] = cls._parse_ladok(data)
        data["profiles"] = cls._parse_profiles(data)
        data["credentials"] = CredentialList.from_list_of_dicts(data.pop("passwords", []))
        if data.get("subject") is not None:
            data["subject"] = SubjectType(data["subject"])

        # unverify any EIDAS identity with loa eidas-nf-low
        # TODO: Remove after next full load-save
        eidas_identity: EIDASIdentity = data["identities"].eidas
        if eidas_identity and (eidas_identity.is_verified and eidas_identity.loa is EIDASLoa.NF_LOW):
            data["identities"].eidas.is_verified = False

        return data

    def _to_dict_transform(self, data: dict[str, Any]) -> dict[str, Any]:
        # serialize complex data
        data["mailAliases"] = self.mail_addresses.to_list_of_dicts()
        data["phone"] = self.phone_numbers.to_list_of_dicts()
        data["passwords"] = self.credentials.to_list_of_dicts()
        data["identities"] = self.identities.to_list_of_dicts()
        if self.tou is not None:
            data["tou"] = self.tou.to_list_of_dicts()
        data["locked_identity"] = self.locked_identity.to_list_of_dicts()
        data["profiles"] = self.profiles.to_list_of_dicts()
        if self.orcid is not None:
            data["orcid"] = self.orcid.to_dict()
        if self.ladok is not None:
            data["ladok"] = self.ladok.to_dict()

        # remove empty strings and empty lists
        for key in list(data.keys()):
            if data[key] in ["", []]:
                if key in ["passwords", "credentials"]:
                    # Empty lists are acceptable for these. When the UserHasNotCompletedSignup
                    # exception is removed, this exception to the rule can be removed too.
                    continue
                del data[key]

        # make sure letter_proofing_data is a list as some old users has a dict instead
        if "letter_proofing_data" in data and isinstance(data["letter_proofing_data"], dict):
            data["letter_proofing_data"] = [data["letter_proofing_data"]]

        return data

    @classmethod
    def from_user(cls: type[TUserSubclass], user: User, private_userdb: BaseDB) -> TUserSubclass:
        """
        This function is only expected to be used with subclasses of User.

        :param user: User instance from AM database
        :param private_userdb: Private UserDB to load modified_ts from

        :return: User subclass instance corresponding to the user in the private database
        """
        # We cast here to avoid importing UserDB at the module level thus creating a circular import
        from eduid.userdb import UserDB

        private_userdb = cast(UserDB[TUserSubclass], private_userdb)

        try:
            private_user = private_userdb.get_user_by_eppn(user.eppn)
        except UserDoesNotExist:
            private_user = None
        logger.debug(f"{cls}: User in private database: {private_user}")

        new_user = cls.from_dict(data=user.to_dict())
        if private_user is not None:
            new_user.modified_ts = private_user.modified_ts
            new_user.meta.modified_ts = private_user.meta.modified_ts
            new_user.meta.created_ts = private_user.meta.created_ts
            new_user.meta.version = private_user.meta.version
            new_user.meta.is_in_database = True
            logger.debug(f"Initialised private user with meta {new_user.meta}")
        return new_user

    @classmethod
    def check_or_use_data(cls, data: dict[str, Any]) -> dict[str, Any]:
        """
        Derived classes can override this method to check that the provided data
        is enough for their purposes, or to deal specially with particular bits of it.

        In case of problems they should raise whatever Exception is appropriate.
        """
        if "passwords" not in data:
            # When this exception is removed, _to_dict_transform (above) should be updated to no longer
            # allow empty lists in 'password' or 'credential'
            raise UserHasNotCompletedSignup(
                "User {!s}/{!s} is incomplete".format(data.get("_id"), data.get("eduPersonPrincipalName"))
            )
        return data

    @classmethod
    def _parse_mail_addresses(cls, data: dict[str, Any]) -> MailAddressList:
        """
        Part of __init__().

        Parse all the different formats of mail+mailAliases attributes in the database.
        """
        _mail_addresses = data.pop("mailAliases", [])
        if "mail" in data:
            # old-style userdb primary e-mail address indicator
            for idx in range(len(_mail_addresses)):
                if _mail_addresses[idx]["email"] == data["mail"]:
                    if "passwords" in data:
                        # Work around a bug where one could signup, not follow the link in the e-mail
                        # and then do a password reset to set a password. The e-mail address is
                        # implicitly verified by the password reset (which must have been done using e-mail).
                        _mail_addresses[idx]["verified"] = True
                    # If a user does not already have a primary mail address promote "mail" to primary if
                    # it is verified
                    _has_primary = any([item.get("primary", False) for item in _mail_addresses])
                    if _mail_addresses[idx].get("verified", False) and not _has_primary:
                        _mail_addresses[idx]["primary"] = True
            data.pop("mail")

        if (
            isinstance(_mail_addresses, list)
            and len(_mail_addresses) == 1
            and _mail_addresses[0].get("verified", False)
        ):
            if not _mail_addresses[0].get("primary", False):
                # A single mail address was not set as Primary until it was verified
                _mail_addresses[0]["primary"] = True

        return MailAddressList.from_list_of_dicts(_mail_addresses)

    @classmethod
    def _parse_phone_numbers(cls, data: dict[str, Any]) -> PhoneNumberList:
        """
        Parse all the different formats of mobile/phone attributes in the database.
        """
        if "mobile" in data:
            _mobile = data.pop("mobile")
            if "phone" not in data:
                # Some users have both 'mobile' and 'phone'. Assume mobile was once transformed
                # to 'phone' but also left behind - so just discard 'mobile'.
                data["phone"] = _mobile
        if "phone" in data:
            _phones = data.pop("phone")
            # Clean up for non verified phone elements that where still primary
            for _this in _phones:
                if not _this.get("verified", False) and _this.get("primary", False):
                    _this["primary"] = False
            _primary = [x for x in _phones if x.get("primary", False)]
            if _phones and not _primary:
                # None of the phone numbers are primary. Promote the first verified
                # entry found (or none if there are no verified entries).
                for _this in _phones:
                    if _this.get("verified", False):
                        _this["primary"] = True
                        break
            data["phone"] = _phones

        _phones = data.pop("phone", [])

        return PhoneNumberList.from_list_of_dicts(_phones)

    @classmethod
    def _parse_identities(cls, data: dict[str, Any]) -> IdentityList:
        """
        Parse identity elements into an IdentityList
        """
        _identities = data.pop("identities", [])
        return IdentityList.from_list_of_dicts(items=_identities)

    @classmethod
    def _parse_tous(cls, data: dict[str, Any]) -> ToUList:
        """
        Parse the ToU acceptance events.
        """
        _tou = data.pop("tou", [])
        return ToUList.from_list_of_dicts(_tou)

    @classmethod
    def _parse_locked_identity(cls, data: dict[str, Any]) -> LockedIdentityList:
        """
        Parse the LockedIdentity elements.
        """
        _locked_identity = data.pop("locked_identity", [])
        return LockedIdentityList.from_list_of_dicts(_locked_identity)

    @classmethod
    def _parse_orcid(cls, data: dict[str, Any]) -> Orcid | None:
        """
        Parse the Orcid element.
        """
        orcid = data.pop("orcid", None)
        if orcid is not None:
            return Orcid.from_dict(orcid)
        return None

    @classmethod
    def _parse_ladok(cls, data: dict[str, Any]) -> Ladok | None:
        """
        Parse the Ladok element.
        """
        ladok = data.pop("ladok", None)
        if ladok is not None:
            return Ladok.from_dict(ladok)
        return None

    @classmethod
    def _parse_profiles(cls, data: dict[str, Any]) -> ProfileList:
        """
        Parse the Profile elements.
        """
        profiles = data.pop("profiles", [])
        if isinstance(profiles, list):
            return ProfileList.from_list_of_dicts(profiles)
        return profiles
