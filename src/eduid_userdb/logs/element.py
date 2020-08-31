# -*- coding: utf-8 -*-
#
# Helper functions to log proofing events.
#

from __future__ import absolute_import

import logging
from dataclasses import dataclass, fields
from typing import Any, Dict, Type, TypeVar

import six

from eduid_userdb.element import Element

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


TLogElementSubclass = TypeVar('TLogElementSubclass', bound='LogElement')


@dataclass
class LogElement(Element):
    """
    """

    # Application creating the log element
    created_by: str

    def validate(self) -> bool:
        element_keys = set([elem.name for elem in fields(Element)])
        self_keys = set([elem.name for elem in fields(self)])
        required_keys = tuple(self_keys - element_keys)
        required_keys += ('created_ts', 'created_by')
        # Check that all keys are accounted for and that no string values are blank
        for key in required_keys:
            data = getattr(self, key)
            if isinstance(data, six.string_types):
                if not data:
                    logger.error('Not enough data to log proofing event: "{}" can not be blank.'.format(key))
                    return False
        return True

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


@dataclass
class _ProofingLogElementRequired:
    """
    Required fields for ProofingLogElement
    """

    # eduPersonPrincipalName
    eppn: str
    # Proofing method version number
    proofing_version: str


@dataclass
class ProofingLogElement(LogElement, _ProofingLogElementRequired):
    """
    """

    # Proofing method name
    proofing_method: str = ''


@dataclass
class _NinProofingLogElementRequired:
    """
    Required fields for NinProofingLogElement
    """

    # National identity number
    nin: str
    # Navet response for users official address
    user_postal_address: Dict[str, Any]


@dataclass
class NinProofingLogElement(ProofingLogElement, _NinProofingLogElementRequired):
    """
    """


@dataclass
class _MailAddressProofingRequired:
    """
    Required fields for MailAddressProofing
    """

    # e-mail address
    mail_address: str
    # Audit reference to help cross reference audit log and events
    reference: str


@dataclass
class MailAddressProofing(ProofingLogElement, _MailAddressProofingRequired):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'e-mail',
        'proofing_version': '2013v1',
        'mail_address': 'mail_address'
        'reference': 'reference id'
    }
    """

    # Proofing method name
    proofing_method: str = 'e-mail'


@dataclass
class _PhoneNumberProofingRequired:
    """
    Required fields for PhoneNumberProofing
    """

    # phone number
    phone_number: str
    # Audit reference to help cross reference audit log and events
    reference: str


@dataclass
class PhoneNumberProofing(ProofingLogElement, _PhoneNumberProofingRequired):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'sms',
        'proofing_version': '2013v1',
        'phone_number': 'phone_number'
        'reference': 'reference id'
    }
    """

    # Proofing method name
    proofing_method: str = 'sms'


@dataclass
class _TeleAdressProofingRequired:
    """
    Required fields for TeleAdressProofing
    """

    # Mobile phone number
    mobile_number: str
    # Reason for mobile phone number match to user
    reason: str


@dataclass
class TeleAdressProofing(NinProofingLogElement, _TeleAdressProofingRequired):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
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

    # Proofing method name
    proofing_method: str = 'TeleAdress'


@dataclass
class _TeleAdressProofingRelationRequired:
    """
    Required fields for TeleAdressProofingRelation
    """

    # NIN of registered user of mobile phone subscription
    mobile_number_registered_to: str
    # Relation of mobile phone subscriber to User
    registered_relation: str
    # Navet response for mobile phone subscriber
    registered_postal_address: str


@dataclass
class TeleAdressProofingRelation(TeleAdressProofing, _TeleAdressProofingRelationRequired):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'TeleAdress',
        'proofing_version': '2014v1',
        'reason': 'match_by_navet',
        'nin': national_identity_number,
        'mobile_number': mobile_number,
        'teleadress_response': {teleadress_response},
        'user_postal_address': {postal_address_from_navet}
        'mobile_number_registered_to': 'registered_national_identity_number',
        'registered_relation': 'registered_relation_to_user'
        'registered_postal_address': {postal_address_from_navet}
    }
    """

    # Proofing method name
    proofing_method: str = 'TeleAdress'


@dataclass
class _LetterProofingRequired:
    """
    Required fields for LetterProofing
    """

    # Name and address the letter was sent to
    letter_sent_to: str
    # Letter service transaction id
    transaction_id: str


@dataclass
class LetterProofing(NinProofingLogElement, _LetterProofingRequired):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'letter',
        'proofing_version': '2016v1',
        'nin': 'national_identity_number',
        'letter_sent_to': {address_letter_was_sent_to},
        'transaction_id': 'transaction_id',
        'user_postal_address': {postal_address_from_navet}
    }
    """

    # Proofing method name
    proofing_method: str = 'letter'


@dataclass
class _SeLegProofingRequired:
    """
    Required fields for SeLegProofing
    """

    # Provider transaction id
    transaction_id: str


@dataclass
class SeLegProofing(NinProofingLogElement, _SeLegProofingRequired):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'se-leg',
        'proofing_version': '2017v1',
        'nin': 'national_identity_number',
        'vetting_by': 'provider who performed the vetting',
        'transaction_id': 'transaction_id',
        'user_postal_address': {postal_address_from_navet}
    }
    """

    # Proofing method name
    proofing_method: str = 'se-leg'
    # Name of the provider who performed the vetting
    vetting_by: str = ''


@dataclass
class _SeLegProofingFrejaEidRequired:
    """
    Required fields for SeLegProofingFrejaEid
    """

    # Data used to initialize the vetting process
    opaque_data: str


@dataclass
class SeLegProofingFrejaEid(SeLegProofing, _SeLegProofingFrejaEidRequired):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
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

    # Name of the provider who performed the vetting
    vetting_by: str = 'Freja eID'


@dataclass
class _OrcidProofingRequired:
    """
    Required fields for OrcidProofing
    """

    # Users unique id
    orcid: str
    # OIDC issuer
    issuer: str
    # OIDC audience
    audience: str


@dataclass
class OrcidProofing(ProofingLogElement, _OrcidProofingRequired):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow(),
        'created_by': 'application',
        'orcid': 'Users orcid',
        'issuer': 'Issuer url',
        'audience': 'Receiving application(s)',
        'proofing_method': 'oidc',
        'proofing_version': '2018v1'
    }
    """

    # Proofing method name
    proofing_method: str = 'oidc'


@dataclass
class _SwedenConnectProofingRequired:
    """
    Required fields for SwedenConnectProofing
    """

    # Provider transaction id
    issuer: str
    # The authentication context class asserted
    authn_context_class: str


@dataclass
class SwedenConnectProofing(NinProofingLogElement, _SwedenConnectProofingRequired):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'swedenconnect',
        'proofing_version': '2018v1',
        'issuer': 'provider who performed the vetting',
        'authn_context_class': 'the asserted authn context class',
        'nin': 'national_identity_number',
        'user_postal_address': {postal_address_from_navet}
    }
    """

    # Proofing method name
    proofing_method: str = 'swedenconnect'


@dataclass
class _MFATokenProofingRequired:
    """
    Required fields for MFATokenProofing
    """

    # Data used to initialize the vetting process
    key_id: str


@dataclass
class MFATokenProofing(SwedenConnectProofing, _MFATokenProofingRequired):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
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

    # Proofing method name
    proofing_method: str = 'swedenconnect'
