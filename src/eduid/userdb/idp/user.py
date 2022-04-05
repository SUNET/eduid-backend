#
# Copyright (c) 2013, 2014, 2015 NORDUnet A/S
#                           2019 SUNET
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

"""
User and user database module.
"""
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from eduid.userdb import User

logger = logging.getLogger(__name__)

# default list of SAML attributes to release
_SAML_ATTRIBUTES = [
    'c',
    'cn',
    'co',
    'displayName',
    'eduPersonAssurance',
    'eduPersonEntitlement',
    'eduPersonOrcid',
    'eduPersonTargetedID',
    'eduPersonPrincipalName',
    'givenName',
    'mail',
    'norEduPersonNIN',
    'personalIdentityNumber',
    'preferredLanguage',
    'schacDateOfBirth',
    'schacPersonalUniqueCode',
    'sn',
]


@dataclass
class SAMLAttributeSettings:
    # Data that needs to come from IdP configuration
    default_eppn_scope: Optional[str]
    default_country: str
    default_country_code: str
    sp_entity_categories: List[str]
    esi_ladok_prefix: str


class IdPUser(User):
    """
    Wrapper class for eduid.userdb.User adding functions useful in the IdP.
    """

    def to_saml_attributes(
        self,
        settings: SAMLAttributeSettings,
        filter_attributes: Optional[List[str]] = None,
    ) -> dict:
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
        logger.debug(f'Discarded non-attributes: {list(attributes_in.keys())!s}')
        # Create and add missing attributes that can be released if correct release policy
        # is applied by pysaml2 for the current metadata
        attributes = make_scoped_eppn(attributes, settings)
        attributes = add_country_attributes(attributes, settings)
        attributes = make_eduperson_unique_id(attributes, self, settings)
        attributes = make_schac_personal_unique_code(attributes, self, settings)
        attributes = add_eduperson_assurance(attributes, self)
        attributes = make_name_attributes(attributes, self)
        attributes = make_nor_eduperson_nin(attributes, self)
        attributes = make_personal_identity_number(attributes, self)
        attributes = make_schac_date_of_birth(attributes, self)
        attributes = make_mail(attributes, self)
        attributes = make_eduperson_orcid(attributes, self)
        logger.info(f'Attributes available for release: {list(attributes.keys())}')
        logger.debug(f'Attributes with values: {attributes}')
        return attributes


def make_scoped_eppn(attributes: dict, settings: SAMLAttributeSettings) -> dict:
    """
    Add scope to unscoped eduPersonPrincipalName attributes before releasing them.

    What scope to add, if any, is currently controlled by the configuration parameter
    `default_eppn_scope'.

    :param attributes: Attributes of a user
    :param settings: IdP configuration settings
    :return: New attributes
    """
    eppn = attributes.get('eduPersonPrincipalName')
    scope = settings.default_eppn_scope
    if not eppn or not scope:
        return attributes
    if '@' not in eppn:
        attributes['eduPersonPrincipalName'] = eppn + '@' + scope
    return attributes


def add_country_attributes(attributes: dict, settings: SAMLAttributeSettings) -> dict:
    if attributes.get('c') is None:
        attributes['c'] = settings.default_country_code
    if attributes.get('co') is None:
        attributes['co'] = settings.default_country
    return attributes


def make_eduperson_unique_id(attributes: dict, user: IdPUser, settings: SAMLAttributeSettings) -> dict:
    """
    eppn@scope (no dash (-) allowed)
    """
    eppn = user.eppn
    scope = settings.default_eppn_scope
    if not eppn or not scope:
        return attributes

    if attributes.get('eduPersonUniqueID') is None:
        unique_id = eppn.replace('-', '')  # hyphen (-) not allowed in eduPersonUniqueID
        attributes['eduPersonUniqueID'] = f'{unique_id}@{scope}'
    return attributes


def add_eduperson_assurance(attributes: Dict[str, Any], user: IdPUser) -> Dict[str, Any]:
    """
    Add an eduPersonAssurance attribute indicating the level of id-proofing
    a user has achieved, regardless of current session authentication strength.

    :param attributes: Attributes of a user
    :param user: The user in question

    :return: New attributes
    """
    attributes['eduPersonAssurance'] = ['http://www.swamid.se/policy/assurance/al1']
    if len(user.nins.verified):
        attributes['eduPersonAssurance'] = ['http://www.swamid.se/policy/assurance/al2']
    return attributes


def make_name_attributes(attributes: dict, user: IdPUser) -> dict:
    # displayName
    if attributes.get('displayName') is None and user.display_name:
        attributes['displayName'] = user.display_name
    # givenName
    if attributes.get('givenName') is None and user.given_name:
        attributes['givenName'] = user.given_name
    # cn (givenName + sn)
    if attributes.get('cn') is None and (user.given_name and user.surname):
        attributes['cn'] = f'{user.given_name} {user.surname}'
    # sn
    if attributes.get('sn') is None and user.surname:
        attributes['sn'] = user.surname
    return attributes


def make_nor_eduperson_nin(attributes: dict, user: IdPUser) -> dict:
    """
    eppn@scope (no dash (-) allowed)
    """
    # TODO: If we ever allow NIN to be something else than personnummer or samordningsnummer
    # TODO: we need to update this function
    if attributes.get('norEduPersonNIN') is not None:
        return attributes

    # A primary element have to be verified but better be defensive
    if user.nins.primary is not None and user.nins.primary.is_verified:
        attributes['norEduPersonNIN'] = user.nins.primary.number
    return attributes


def make_personal_identity_number(attributes: dict, user: IdPUser) -> dict:
    """
    Only "personnummer" or "samordningsnummer" is allowed as personalIdentityNumber.
    """
    # TODO: If we ever allow NIN to be something else than personnummer or samordningsnummer
    # TODO: we need to update this function
    if attributes.get('personalIdentityNumber') is not None:
        return attributes

    # A primary element have to be verified but better be defensive
    if user.nins.primary is not None and user.nins.primary.is_verified:
        attributes['personalIdentityNumber'] = user.nins.primary.number
    return attributes


def make_schac_date_of_birth(attributes: dict, user: IdPUser) -> dict:
    """
    Format: YYYYMMDD, only numeric
    """
    if attributes.get('schacDateOfBirth') is not None:
        return attributes

    # A primary element have to be verified but better be defensive
    if user.nins.primary is not None and user.nins.primary.is_verified:
        try:
            parsed_date = datetime.strptime(user.nins.primary.number[:8], '%Y%m%d')
            attributes['schacDateOfBirth'] = parsed_date.strftime('%Y%m%d')
        except ValueError:
            logger.exception('Unable to parse user nin to date of birth')
            logger.debug(f'User nins: {user.nins}')
    return attributes


def make_mail(attributes: dict, user: IdPUser) -> dict:
    if attributes.get('mail') is not None:
        return attributes

    # A primary element have to be verified but better be defensive
    if user.mail_addresses.primary is not None and user.mail_addresses.primary.is_verified:
        attributes['mail'] = user.mail_addresses.primary.email
    return attributes


def make_eduperson_orcid(attributes: dict, user: IdPUser) -> dict:
    # TODO: Should the user be AL2 for us to release this?
    #   Should we disallow there to be more than one eduID user with the same orcid?
    if attributes.get('eduPersonOrcid') is not None:
        return attributes

    if user.orcid is not None and user.orcid.is_verified:
        attributes['eduPersonOrcid'] = user.orcid.id
    return attributes


def _make_user_esi(user: IdPUser, settings: SAMLAttributeSettings) -> Optional[str]:
    # do not release Ladok ESI for an unverified user as you need to be verified to connect to Ladok
    if user.nins.primary is not None and user.nins.primary.is_verified:
        if user.ladok is not None and user.ladok.is_verified:
            return f'{settings.esi_ladok_prefix}{user.ladok.external_id}'
    return None


def make_schac_personal_unique_code(attributes: dict, user: IdPUser, settings: SAMLAttributeSettings) -> dict:
    """
    schacPersonalUniqueCode could be something other than ESI, but we have no usecase for anything else
    at the moment
    """
    if attributes.get('schacPersonalUniqueCode') is not None:
        return attributes

    unique_code = None
    # if SP has entity category https://myacademicid.org/entity-categories/esi we should release ESI as
    # personal unique code
    if 'https://myacademicid.org/entity-categories/esi' in settings.sp_entity_categories:
        unique_code = _make_user_esi(user=user, settings=settings)

    if unique_code is not None:
        attributes['schacPersonalUniqueCode'] = unique_code
    return attributes
