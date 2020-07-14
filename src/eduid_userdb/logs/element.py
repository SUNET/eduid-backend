# -*- coding: utf-8 -*-
#
# Helper functions to log proofing events.
#

from __future__ import absolute_import

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict
import logging

import six

from eduid_userdb.element import Element

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


@dataclass
class _LogElementRequired:
    created_by: str


@dataclass
class LogElement(Element, _LogElementRequired):
    created_ts: datetime = field(default_factory=datetime.utcnow)


@dataclass
class _ProofingLogElementRequired:
    eppn: str
    proofing_version: str


@dataclass
class ProofingLogElement(LogElement, _ProofingLogElementRequired):
    """
    """
    proofing_method: str = ''


@dataclass
class _NinProofingLogElementRequired:
    nin: str
    user_postal_address: str


@dataclass
class NinProofingLogElement(ProofingLogElement, _NinProofingLogElementRequired):
    """
    """


@dataclass
class _MailAddressProofingRequired:
    mail_address: str
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
    proofing_method: str = 'e-mail'


@dataclass
class _PhoneNumberProofingRequired:
    phone_number: str
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
    proofing_method: str = 'sms'


@dataclass
class _TeleAdressProofingRequired:
    mobile_number: str
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
    proofing_method: str = 'TeleAdress'


@dataclass
class _TeleAdressProofingRelationRequired:
    mobile_number_registered_to: str
    registered_relation: str
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
    proofing_method: str = 'TeleAdress'


@dataclass
class _LetterProofingRequired:
    letter_sent_to: str
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
    proofing_method: str = 'letter'


@dataclass
class _SeLegProofingRequired:
    vetting_by: str
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
    proofing_method: str = 'se-leg'


@dataclass
class _SeLegProofingFrejaEidRequired:
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
    proofing_method: str = 'se-leg'


@dataclass
class _OrcidProofingRequired:
    opaque_data: str


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
    proofing_method: str = 'oidc'


@dataclass
class _SwedenConnectProofingRequired:
    issuer: str
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
    proofing_method: str = 'swedenconnect'


@dataclass
class _MFATokenProofingRequired:
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
    proofing_method: str = 'swedenconnect'
