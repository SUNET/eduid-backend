# -*- coding: utf-8 -*-
#
# Helper functions to log proofing events.
#
import logging
from typing import Any, Dict, List, Optional, Type, TypeVar

from eduid.userdb.element import Element, ElementKey

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


TLogElementSubclass = TypeVar('TLogElementSubclass', bound='LogElement')
TNinProofingLogElementSubclass = TypeVar('TNinProofingLogElementSubclass', bound='NinProofingLogElement')


class LogElement(Element):
    """
    """

    # Application creating the log element
    created_by: str

    class Config:
        min_anystr_length = 1  # No empty strings allowed in log records

    @classmethod
    def _from_dict_transform(cls: Type[TLogElementSubclass], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        data = super()._from_dict_transform(data)

        if 'eduPersonPrincipalName' in data:
            data['eppn'] = data.pop('eduPersonPrincipalName')

        return data

    def _to_dict_transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform data kept in pythonic format into eduid format.
        """
        if 'eppn' in data:
            data['eduPersonPrincipalName'] = data.pop('eppn')

        data = super()._to_dict_transform(data)

        return data


class ProofingLogElement(LogElement):
    """
    """

    # eduPersonPrincipalName
    eppn: str
    # Proofing method version number
    proofing_version: str
    # Proofing method name
    proofing_method: str = ''


class NinProofingLogElement(ProofingLogElement):
    """
    """

    # National identity number
    nin: str
    # Navet response for users official address
    user_postal_address: Dict[str, Any]


class MailAddressProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'e-mail',
        'proofing_version': '2013v1',
        'mail_address': 'mail_address',
        'reference': 'reference id'
    }
    """

    # e-mail address
    mail_address: str
    # Audit reference to help cross reference audit log and events
    reference: str
    # Proofing method name
    proofing_method: str = 'e-mail'


class PhoneNumberProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'sms',
        'proofing_version': '2013v1',
        'phone_number': 'phone_number'
        'reference': 'reference id'
    }
    """

    # phone number
    phone_number: str
    # Audit reference to help cross reference audit log and events
    reference: str
    # Proofing method name
    proofing_method: str = 'sms'


class TeleAdressProofing(NinProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'TeleAdress',
        'proofing_version': '2014v1',
        'reason': 'matched',
        'nin': national_identity_number,
        'mobile_number': mobile_number,
        'teleadress_response': {teleadress_response},
        'user_postal_address': {postal_address_from_navet}
    }
    """

    # Mobile phone number
    mobile_number: str
    # Reason for mobile phone number match to user
    reason: str
    # Proofing method name
    proofing_method: str = 'TeleAdress'


class TeleAdressProofingRelation(TeleAdressProofing):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'TeleAdress',
        'proofing_version': '2014v1',
        'reason': 'match_by_navet',
        'nin': national_identity_number,
        'mobile_number': mobile_number,
        'teleadress_response': {teleadress_response},
        'user_postal_address': {postal_address_from_navet},
        'mobile_number_registered_to': 'registered_national_identity_number',
        'registered_relation': 'registered_relation_to_user'
        'registered_postal_address': {postal_address_from_navet}
    }
    """

    # NIN of registered user of mobile phone subscription
    mobile_number_registered_to: str
    # Relation of mobile phone subscriber to User
    registered_relation: List[str]
    # Navet response for mobile phone subscriber
    registered_postal_address: Dict[str, Any]
    # Proofing method name
    proofing_method: str = 'TeleAdress'


class LetterProofing(NinProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'letter',
        'proofing_version': '2016v1',
        'nin': 'national_identity_number',
        'letter_sent_to': {address_letter_was_sent_to},
        'transaction_id': 'transaction_id',
        'user_postal_address': {postal_address_from_navet}
    }
    """

    # Name and address the letter was sent to
    letter_sent_to: Dict[str, Any]
    # Letter service transaction id
    transaction_id: str
    # Proofing method name
    proofing_method: str = 'letter'


class SeLegProofing(NinProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'se-leg',
        'proofing_version': '2017v1',
        'nin': 'national_identity_number',
        'vetting_by': 'provider who performed the vetting',
        'transaction_id': 'transaction_id',
        'user_postal_address': {postal_address_from_navet}
    }
    """

    # Provider transaction id
    transaction_id: str
    # Proofing method name
    proofing_method: str = 'se-leg'
    # Name of the provider who performed the vetting
    vetting_by: str = ''


class SeLegProofingFrejaEid(SeLegProofing):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'se-leg',
        'proofing_version': '2017v1',
        'nin': 'national_identity_number',
        'vetting_by': 'provider who performed the vetting',
        'transaction_id': 'Freja eID transaction_id',
        'opaque_data: 'Data used to initialize the vetting process',
        'user_postal_address': {postal_address_from_navet}
    }
    """

    # Data used to initialize the vetting process
    opaque_data: str
    # Name of the provider who performed the vetting
    vetting_by: str = 'Freja eID'


class OrcidProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'orcid': 'Users orcid',
        'issuer': 'Issuer url',
        'audience': 'Receiving application(s)',
        'proofing_method': 'oidc',
        'proofing_version': '2018v1'
    }
    """

    # Users unique id
    orcid: str
    # OIDC issuer
    issuer: str
    # OIDC audience
    audience: List[str]
    # Proofing method name
    proofing_method: str = 'oidc'


class SwedenConnectProofing(NinProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'swedenconnect',
        'proofing_version': '2018v1',
        'issuer': 'provider who performed the vetting',
        'authn_context_class': 'the asserted authn context class',
        'nin': 'national_identity_number',
        'user_postal_address': {postal_address_from_navet}
    }
    """

    # Provider transaction id
    issuer: str
    # The authentication context class asserted
    authn_context_class: str
    # Proofing method name
    proofing_method: str = 'swedenconnect'


class MFATokenProofing(SwedenConnectProofing):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'swedenconnect',
        'proofing_version': '2018v1',
        'issuer': 'provider who performed the vetting',
        'authn_context_class': 'the asserted authn context class',
        'key_id: 'Key id of token vetted',
        'nin': 'national_identity_number',
        'user_postal_address': {postal_address_from_navet}
    }
    """

    # Data used to initialize the vetting process
    key_id: str
    # Proofing method name
    proofing_method: str = 'swedenconnect'


class NameUpdateProofing(NinProofingLogElement):
    """
    Used when a user request an update of their name from Navet.

    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'Navet name update',
        'proofing_version': '2021v1',
        'nin': national_identity_number,
        'user_postal_address': {postal_address_from_navet}
        'previous_given_name': 'given name'
        'previous_surname': 'surname'
    }
    """

    # Previous given name
    previous_given_name: Optional[str]
    # Previous surname
    previous_surname: Optional[str]
    # Proofing method name
    proofing_method: str = 'Navet name update'


class LadokProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'eduid_ladok',
        'proofing_version': '2021v1',
        'nin': 'nin',
        'external_id': 'external Ladok user id',
        'university_abbr': 'university abbreviation'
    }
    """

    nin: str
    # Ladok persistent external user id
    external_id: str
    # University name abbreviation
    university_abbr: str
    proofing_method: str = 'eduid_ladok'
