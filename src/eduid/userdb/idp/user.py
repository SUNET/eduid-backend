"""
User and user database module.
"""

import logging
from dataclasses import dataclass
from enum import StrEnum, unique
from typing import Any

from eduid.common.models.saml2 import EduidAuthnContextClass
from eduid.userdb import User

logger = logging.getLogger(__name__)

# list of supported SAML attributes we can release
SUPPORTED_SAML_ATTRIBUTES = [
    "c",
    "cn",
    "co",
    "displayName",
    "eduPersonAssurance",
    "eduPersonEntitlement",
    "eduPersonOrcid",
    "eduPersonPrincipalName",
    "eduPersonTargetedID",
    "givenName",
    "mail",
    "mailLocalAddress",
    "norEduPersonLegalName",
    "norEduPersonNIN",
    "pairwise-id",
    "personalIdentityNumber",
    "preferredLanguage",
    "schacDateOfBirth",
    "schacPersonalUniqueCode",
    "sn",
    "subject-id",
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
    authn_context_class: EduidAuthnContextClass
    pairwise_id: str | None = None


@unique
class SubjectIDRequest(StrEnum):
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
        filter_attributes: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Return a dict of SAML attributes for a user.

        Note that this is _all_ parts of the user that this IdP knows how to express as
        SAML attributes. It is not necessarily the attributes that will actually be released.

        :param settings: Settings for attribute creation from IdP config
        :param filter_attributes: Filter to apply

        :return: SAML attributes
        """
        attributes: dict[str, Any] = {}

        if filter_attributes is None:
            filter_attributes = SUPPORTED_SAML_ATTRIBUTES

        # Create and add missing attributes that can be released if correct release policy
        # is applied by pysaml2 for the current metadata
        attributes = make_scoped_eppn(attributes, self, settings)
        attributes = add_country_attributes(attributes, settings)
        attributes = make_schac_personal_unique_code(attributes, self, settings)
        attributes = add_pairwise_or_subject_id(attributes, self, settings)
        attributes = add_eduperson_assurance(attributes, self)
        attributes = make_name_attributes(attributes, self, settings)
        attributes = make_nor_eduperson_nin(attributes, self)
        attributes = make_personal_identity_number(attributes, self)
        attributes = make_schac_date_of_birth(attributes, self)
        attributes = make_mail(attributes, self)
        attributes = make_eduperson_orcid(attributes, self)
        attributes = add_mail_local_address(attributes, self)
        attributes = make_eduperson_entitlement(attributes, self)
        attributes = add_preferred_language(attributes, self)

        logger.info(f"Attributes available for release: {list(attributes.keys())}")
        logger.debug(f"Attributes with values: {attributes}")

        filtered_attributes = {}
        for approved in filter_attributes:
            if approved in attributes:
                filtered_attributes[approved] = attributes.pop(approved)
        logger.info(f"Attributes available for release AFTER filter: {list(filtered_attributes.keys())}")
        logger.debug(f"Attributes filtered out: {attributes}")

        return filtered_attributes


def make_scoped_eppn(attributes: dict[str, Any], user: IdPUser, settings: SAMLAttributeSettings) -> dict[str, Any]:
    """
    Add scope to unscoped eduPersonPrincipalName attributes before releasing them.

    What scope to add, if any, is currently controlled by the configuration parameter
    `default_eppn_scope'.
    """
    eppn = user.eppn
    scope = settings.default_eppn_scope

    if not scope:
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


def make_name_attributes(attributes: dict[str, Any], user: IdPUser, settings: SAMLAttributeSettings) -> dict[str, Any]:
    # if the request comes from Swamid, we can use the user chosen given name
    # treat all requests as from Swamid unless the authn context class is DIGG_LOA2
    swamid_request = settings.authn_context_class != EduidAuthnContextClass.DIGG_LOA2

    # givenName
    if attributes.get("givenName") is None and user.given_name:
        attributes["givenName"] = user.given_name
        if swamid_request and user.chosen_given_name:
            attributes["givenName"] = user.chosen_given_name

    # sn
    if attributes.get("sn") is None and user.surname:
        attributes["sn"] = user.surname

    # norEduPersonLegalName
    if attributes.get("norEduPersonLegalName") is None and user.legal_name:
        attributes["norEduPersonLegalName"] = user.legal_name
    # fill users legal name if not set and user has a verified identity
    if user.legal_name is None and user.identities.is_verified:
        attributes["norEduPersonLegalName"] = f"{user.given_name} {user.surname}"

    # displayName
    if attributes.get("displayName") is None and attributes.get("givenName") and attributes.get("sn"):
        attributes["displayName"] = f"{attributes['givenName']} {attributes['sn']}"

    # cn (use displayName)
    if attributes.get("cn") is None and attributes.get("displayName"):
        attributes["cn"] = attributes["displayName"]

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


def _make_user_esi(user: IdPUser, settings: SAMLAttributeSettings) -> str | None:
    # do not release Ladok ESI for an unverified user as you need to be verified to connect to Ladok
    if user.identities.is_verified:
        if user.ladok is not None and user.ladok.is_verified:
            return f"{settings.esi_ladok_prefix}{user.ladok.external_id}"
    return None


def make_schac_personal_unique_code(
    attributes: dict[str, Any], user: IdPUser, settings: SAMLAttributeSettings
) -> dict[str, Any]:
    """
    schacPersonalUniqueCode could be something other than ESI, but we have no use case for anything else
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


def make_eduperson_entitlement(attributes: dict[str, Any], user: IdPUser) -> dict[str, Any]:
    """
    Adds the eduPersonEntitlement attribute to the attributes dictionary.
    """
    if attributes.get("eduPersonEntitlement") is not None:
        return attributes

    if user.entitlements is not None:
        attributes["eduPersonEntitlement"] = user.entitlements
    return attributes


def add_preferred_language(attributes: dict[str, Any], user: IdPUser) -> dict[str, Any]:
    """
    Adds the preferred language to the attributes dictionary.
    """
    if attributes.get("preferredLanguage") is not None:
        return attributes

    if user.language is not None:
        attributes["preferredLanguage"] = user.language
    return attributes
