"""
User and user database module.
"""

import logging
from dataclasses import dataclass
from enum import Enum, unique
from typing import Any, Optional

from eduid.userdb import User

logger = logging.getLogger(__name__)

# default list of SAML attributes to release
_SAML_ATTRIBUTES = [
    "c",
    "cn",
    "co",
    "displayName",
    "eduPersonAssurance",
    "eduPersonEntitlement",
    "eduPersonOrcid",
    "eduPersonTargetedID",
    "eduPersonPrincipalName",
    "givenName",
    "mail",
    "norEduPersonNIN",
    "personalIdentityNumber",
    "preferredLanguage",
    "schacDateOfBirth",
    "schacPersonalUniqueCode",
    "sn",
]


@dataclass
class SAMLAttributeSettings:
    # Data that needs to come from IdP configuration
    default_eppn_scope: str
    default_country: str
    default_country_code: str
    sp_entity_categories: list[str]
    sp_subject_id_request: list[str]
    esi_ladok_prefix: str
    pairwise_id: Optional[str] = None


@unique
class SubjectIDRequest(str, Enum):
    ANY = "any"
    NONE = "none"
    PAIRWISE_ID = "pairwise-id"
    SUBJECT_ID = "subject-id"


class IdPUser(User):
    """
    Wrapper class for eduid.userdb.User adding functions useful in the IdP.
    """

    is_managed_account: bool = False

    def _to_dict_transform(self, data: dict[str, Any]) -> dict[str, Any]:
        data = super()._to_dict_transform(data)
        # Remove the is_managed_account as it is only for the ephemeral IdP user and should not be saved
        # or used for instantiating a new user object
        del data["is_managed_account"]
        return data

    def to_saml_attributes(
        self,
        settings: SAMLAttributeSettings,
        filter_attributes: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """
        Return a dict of SAML attributes for a user.

        Note that this is _all_ parts of the user that this IdP knows how to express as
        SAML attributes. It is not necessarily the attributes that will actually be released.

        :param settings: Settings for attribute creation from IdP config
        :param filter_attributes: Filter to apply

        :return: SAML attributes
        """
        if filter_attributes is None:
            filter_attributes = _SAML_ATTRIBUTES
        attributes_in = self.to_dict()
        attributes = {}
        for approved in filter_attributes:
            if approved in attributes_in:
                attributes[approved] = attributes_in.pop(approved)
        logger.debug(f"Discarded non-attributes: {list(attributes_in.keys())!s}")
        # Create and add missing attributes that can be released if correct release policy
        # is applied by pysaml2 for the current metadata
        attributes = make_scoped_eppn(attributes, settings)
        attributes = add_country_attributes(attributes, settings)
        attributes = make_schac_personal_unique_code(attributes, self, settings)
        attributes = add_pairwise_or_subject_id(attributes, self, settings)
        attributes = add_eduperson_assurance(attributes, self)
        attributes = make_name_attributes(attributes, self)
        attributes = make_nor_eduperson_nin(attributes, self)
        attributes = make_personal_identity_number(attributes, self)
        attributes = make_schac_date_of_birth(attributes, self)
        attributes = make_mail(attributes, self)
        attributes = make_eduperson_orcid(attributes, self)
        attributes = add_mail_local_address(attributes, self)

        logger.info(f"Attributes available for release: {list(attributes.keys())}")
        logger.debug(f"Attributes with values: {attributes}")
        return attributes


def make_scoped_eppn(attributes: dict[str, Any], settings: SAMLAttributeSettings) -> dict[str, Any]:
    """
    Add scope to unscoped eduPersonPrincipalName attributes before releasing them.

    What scope to add, if any, is currently controlled by the configuration parameter
    `default_eppn_scope'.

    :param attributes: Attributes of a user
    :param settings: IdP configuration settings
    :return: New attributes
    """
    eppn = attributes.get("eduPersonPrincipalName")
    scope = settings.default_eppn_scope
    if not eppn or not scope:
        return attributes
    if "@" not in eppn:
        attributes["eduPersonPrincipalName"] = eppn + "@" + scope
    return attributes


def add_country_attributes(attributes: dict[str, Any], settings: SAMLAttributeSettings) -> dict[str, Any]:
    if attributes.get("c") is None:
        attributes["c"] = settings.default_country_code
    if attributes.get("co") is None:
        attributes["co"] = settings.default_country
    return attributes


def add_eduperson_assurance(attributes: dict[str, Any], user: IdPUser) -> dict[str, Any]:
    """
    Add an eduPersonAssurance attribute indicating the level of id-proofing
    a user has achieved, regardless of current session authentication strength.

    :param attributes: Attributes of a user
    :param user: The user in question

    :return: New attributes
    """
    attributes["eduPersonAssurance"] = ["http://www.swamid.se/policy/assurance/al1"]
    if user.identities.is_verified:
        attributes["eduPersonAssurance"] = ["http://www.swamid.se/policy/assurance/al2"]
    return attributes


def make_name_attributes(attributes: dict[str, Any], user: IdPUser) -> dict[str, Any]:
    # displayName
    if attributes.get("displayName") is None and user.display_name:
        attributes["displayName"] = user.display_name
    # givenName
    if attributes.get("givenName") is None and user.given_name:
        attributes["givenName"] = user.given_name
    # cn (givenName + sn)
    if attributes.get("cn") is None and (user.given_name and user.surname):
        attributes["cn"] = f"{user.given_name} {user.surname}"
    # sn
    if attributes.get("sn") is None and user.surname:
        attributes["sn"] = user.surname
    return attributes


def make_nor_eduperson_nin(attributes: dict[str, Any], user: IdPUser) -> dict[str, Any]:
    """
    eppn@scope (no dash (-) allowed)
    """
    # TODO: If we ever allow NIN to be something else than personnummer or samordningsnummer
    # TODO: we need to update this function
    if attributes.get("norEduPersonNIN") is not None:
        return attributes

    if user.identities.nin is not None and user.identities.nin.is_verified:
        attributes["norEduPersonNIN"] = user.identities.nin.number
    return attributes


def make_personal_identity_number(attributes: dict[str, Any], user: IdPUser) -> dict[str, Any]:
    """
    Only "personnummer" or "samordningsnummer" is allowed as personalIdentityNumber.
    """
    # TODO: If we ever allow NIN to be something else than personnummer or samordningsnummer
    # TODO: we need to update this function
    if attributes.get("personalIdentityNumber") is not None:
        return attributes

    if user.identities.nin is not None and user.identities.nin.is_verified:
        attributes["personalIdentityNumber"] = user.identities.nin.number
    return attributes


def make_schac_date_of_birth(attributes: dict[str, Any], user: IdPUser) -> dict[str, Any]:
    """
    Format: YYYYMMDD, only numeric
    """
    if attributes.get("schacDateOfBirth") is not None:
        return attributes

    if user.identities.is_verified and user.identities.date_of_birth is not None:
        attributes["schacDateOfBirth"] = user.identities.date_of_birth.strftime("%Y%m%d")
    return attributes


def make_mail(attributes: dict[str, Any], user: IdPUser) -> dict[str, Any]:
    if attributes.get("mail") is not None:
        return attributes

    # A primary element have to be verified but better be defensive
    if user.mail_addresses.primary is not None and user.mail_addresses.primary.is_verified:
        attributes["mail"] = user.mail_addresses.primary.email
    return attributes


def make_eduperson_orcid(attributes: dict[str, Any], user: IdPUser) -> dict[str, Any]:
    # TODO: Should the user be AL2 for us to release this?
    #   Should we disallow there to be more than one eduID user with the same orcid?
    if attributes.get("eduPersonOrcid") is not None:
        return attributes

    if user.orcid is not None and user.orcid.is_verified:
        attributes["eduPersonOrcid"] = user.orcid.id
    return attributes


def _make_user_esi(user: IdPUser, settings: SAMLAttributeSettings) -> Optional[str]:
    # do not release Ladok ESI for an unverified user as you need to be verified to connect to Ladok
    if user.identities.is_verified:
        if user.ladok is not None and user.ladok.is_verified:
            return f"{settings.esi_ladok_prefix}{user.ladok.external_id}"
    return None


def make_schac_personal_unique_code(
    attributes: dict[str, Any], user: IdPUser, settings: SAMLAttributeSettings
) -> dict[str, Any]:
    """
    schacPersonalUniqueCode could be something other than ESI, but we have no usecase for anything else
    at the moment
    """
    if attributes.get("schacPersonalUniqueCode") is not None:
        return attributes

    unique_code = None
    # if SP has entity category https://myacademicid.org/entity-categories/esi we should release ESI as
    # personal unique code
    if "https://myacademicid.org/entity-categories/esi" in settings.sp_entity_categories:
        unique_code = _make_user_esi(user=user, settings=settings)

    if unique_code is not None:
        attributes["schacPersonalUniqueCode"] = unique_code
    return attributes


def add_mail_local_address(attributes: dict[str, Any], user: IdPUser) -> dict[str, Any]:
    if attributes.get("mailLocalAddress") is not None:
        return attributes

    attributes["mailLocalAddress"] = [item.email for item in user.mail_addresses.to_list() if item.is_verified]
    return attributes


def add_pairwise_or_subject_id(
    attributes: dict[str, Any], user: IdPUser, settings: SAMLAttributeSettings
) -> dict[str, Any]:
    """
    Add a pairwise or subject ID attribute to the attributes' dict.
    """

    refeds_access_ec = [
        "https://refeds.org/category/personalized",
        "https://refeds.org/category/pseudonymous",
        "https://refeds.org/category/anonymous",
    ]
    # if the SP has any REFEDS access category, add both subject-id and pairwise-id and let pysaml2 sort it out
    # when filtering attributes for that category
    if set(settings.sp_entity_categories).intersection(refeds_access_ec):
        if attributes.get("pairwise-id") is None and settings.pairwise_id is not None:
            attributes["pairwise-id"] = settings.pairwise_id
        if attributes.get("subject-id") is None:
            attributes["subject-id"] = f"{user.eppn}@{settings.default_eppn_scope}"
        return attributes

    # for any other entity category, add the type of id that the SP has requested
    if (
        SubjectIDRequest.PAIRWISE_ID.value in settings.sp_subject_id_request
        or SubjectIDRequest.ANY.value in settings.sp_subject_id_request
    ):
        if attributes.get("pairwise-id") is None and settings.pairwise_id is not None:
            attributes["pairwise-id"] = settings.pairwise_id
    elif SubjectIDRequest.SUBJECT_ID.value in settings.sp_subject_id_request:
        if attributes.get("subject-id") is None:
            attributes["subject-id"] = f"{user.eppn}@{settings.default_eppn_scope}"

    return attributes
