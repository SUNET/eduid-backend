#
# Helper functions to log proofing events.
#
import logging
from datetime import datetime
from typing import Any, Optional, TypeVar, Union
from uuid import UUID

import bson
from fido_mds.models.fido_mds import Entry as FidoMetadataEntry
from pydantic import ConfigDict, Field

from eduid.common.models.amapi_user import Reason, Source
from eduid.common.rpc.msg_relay import DeregistrationInformation, FullPostalAddress
from eduid.userdb.element import Element
from eduid.userdb.identity import IdentityProofingMethod

__author__ = "lundberg"

from fido_mds.models.webauthn import AttestationFormat

logger = logging.getLogger(__name__)

TLogElementSubclass = TypeVar("TLogElementSubclass", bound="LogElement")
TNinProofingLogElementSubclass = TypeVar("TNinProofingLogElementSubclass", bound="NinProofingLogElement")
TNinEIDProofingLogElementSubclass = TypeVar("TNinEIDProofingLogElementSubclass", bound="NinEIDProofingLogElement")
TNinNavetProofingLogElementSubclass = TypeVar("TNinNavetProofingLogElementSubclass", bound="NinNavetProofingLogElement")
TForeignIdProofingLogElementSubclass = TypeVar(
    "TForeignIdProofingLogElementSubclass", bound="ForeignIdProofingLogElement"
)


class LogElement(Element):
    """ """

    # Application creating the log element
    created_by: str
    model_config = ConfigDict(str_min_length=1)

    @classmethod
    def _from_dict_transform(cls: type[TLogElementSubclass], data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        data = super()._from_dict_transform(data)

        if "eduPersonPrincipalName" in data:
            data["eppn"] = data.pop("eduPersonPrincipalName")

        return data

    def _to_dict_transform(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data kept in pythonic format into eduid format.
        """
        if "eppn" in data:
            data["eduPersonPrincipalName"] = data.pop("eppn")

        data = super()._to_dict_transform(data)

        return data


class ProofingLogElement(LogElement):
    """ """

    # eduPersonPrincipalName
    eppn: str
    # Proofing method version number
    proofing_version: str
    # Proofing method name
    proofing_method: str = ""


class NinProofingLogElement(ProofingLogElement):
    # National identity number
    nin: str


class NinEIDProofingLogElement(NinProofingLogElement):
    # The users name from the EID service is used
    given_name: str
    surname: str


class NinNavetProofingLogElement(NinProofingLogElement):
    # Navet response for users official address
    user_postal_address: FullPostalAddress
    # Navet response for users deregistration information (used if official address is missing)
    deregistration_information: Optional[DeregistrationInformation] = None


class ForeignIdProofingLogElement(ProofingLogElement):
    given_name: str
    surname: str
    date_of_birth: str
    country_code: str


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
    proofing_method: str = "e-mail"


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
    proofing_method: str = "sms"


class TeleAdressProofing(NinNavetProofingLogElement):
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
    proofing_method: str = IdentityProofingMethod.TELEADRESS.value


# DEPRECATED: This proofing is deprecated
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
        'registered_deregistration_information': {deregistration information from navet]
    }
    """

    # NIN of registered user of mobile phone subscription
    mobile_number_registered_to: str
    # Relation of mobile phone subscriber to User
    registered_relation: list[str]
    # Navet response for mobile phone subscriber
    registered_postal_address: FullPostalAddress
    # Navet response for mobile phone subscriber deregistration information (used if official address is missing)
    registered_deregistration_information: Optional[DeregistrationInformation] = None
    # Proofing method name
    proofing_method: str = IdentityProofingMethod.TELEADRESS.value


class LetterProofing(NinNavetProofingLogElement):
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
    letter_sent_to: dict[str, Any]
    # Letter service transaction id
    transaction_id: str
    # Proofing method name
    proofing_method: str = IdentityProofingMethod.LETTER.value


class SeLegProofing(NinNavetProofingLogElement):
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
    proofing_method: str = IdentityProofingMethod.SE_LEG.value
    # Name of the provider who performed the vetting
    vetting_by: str = ""


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
    vetting_by: str = "Freja eID"


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
    audience: list[str]
    # Proofing method name
    proofing_method: str = "oidc"


class SwedenConnectProofing(NinEIDProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'swedenconnect',
        'proofing_version': '2023v1',
        'issuer': 'provider who performed the vetting',
        'authn_context_class': 'the asserted authn context class',
        'nin': 'national_identity_number',
        'given_name': 'name',
        'surname': 'name',
    }

    Proofing version history:
    2018v1 - inital deployment
    2023v1 - Navet lookup is no longer performed per proofing
    """

    # Identity issuer
    issuer: str
    # The authentication context class asserted
    authn_context_class: str
    # Proofing method name
    proofing_method: str = IdentityProofingMethod.SWEDEN_CONNECT.value


class SwedenConnectEIDASProofing(ForeignIdProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'swedenconnect',
        'proofing_version': '2022v1',
        'issuer': 'provider who performed the vetting',
        'authn_context_class': 'the asserted authn context class',
        'prid': 'Sweden connect provisional identifier',
        'prid_persistence': 'prid persistence indicator',
        'eidas_person_identifier': 'eIDAS uniqueness identifier for natural persons',
        'transaction_identifier': 'transaction id',
        'mapped_personal_identity_number': 'mapped nin',
        'personal_identity_number_binding': 'how nin is mapped'
    }
    """

    # Identity issuer
    issuer: str
    # The authentication context class asserted
    authn_context_class: str
    # Provisional identifier
    prid: str
    # Provisional identifier persistence indicator
    prid_persistence: str
    # eIDAS uniqueness identifier for natural persons
    eidas_person_identifier: str
    # Transaction identifier
    transaction_identifier: str
    # if and when a nin can be mapped to a person these will be used
    mapped_personal_identity_number: Optional[str] = None
    personal_identity_number_binding: Optional[str] = None
    # Proofing method name
    proofing_method: str = IdentityProofingMethod.SWEDEN_CONNECT.value


class SvipeIDNINProofing(NinEIDProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'svipe_id',
        'proofing_version': '2023v2',
        'svipe_id': 'unique identifier for the user',
        'document_type': 'type of document used for identification',
        'document_number': 'document number',
        'nin': 'national_identity_number',
        'given_name': 'name',
        'surname': 'name',
    }

    Proofing version history:
    2023v1 - inital deployment
    2023v2 - Navet lookup is no longer performed per proofing
    """

    # unique identifier
    svipe_id: str
    # transaction id
    transaction_id: str
    # document type (standardized english)
    document_type: str
    # document number
    document_number: str
    # Proofing method name
    proofing_method: str = IdentityProofingMethod.SVIPE_ID.value


class SvipeIDForeignProofing(ForeignIdProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'svipe_id',
        'proofing_version': '2022v1',
        'svipe_id': 'unique identifier for the user',
        'document_type': 'type of document used for identification',
        'document_number': 'document number',
        'issuing_country': 'country of issuance',
    }
    """

    # unique identifier
    svipe_id: str
    # transaction id
    transaction_id: str
    # document administrative number
    administrative_number: Optional[str]
    # document type (standardized english)
    document_type: str
    # document number
    document_number: str
    # issuing country
    issuing_country: str
    # Proofing method name
    proofing_method: str = IdentityProofingMethod.SVIPE_ID.value


class BankIDProofing(NinEIDProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'bankid',
        'proofing_version': '2023v1',
        'nin': 'national_identity_number',
        'given_name': 'name',
        'surname': 'name',
        'transaction_id': 'transaction id',
    }

    Proofing version history:
    2023v1 - inital deployment
    """

    # Transaction ID from BankID
    transaction_id: str
    # Proofing method name
    proofing_method: str = IdentityProofingMethod.BANKID.value


class FrejaEIDNINProofing(NinEIDProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'freja_eid',
        'proofing_version': '2024v1',
        'user_id': 'unique identifier for the user',
        'document_type': 'type of document used for identification',
        'document_number': 'document number',
        'nin': 'national_identity_number',
        'given_name': 'name',
        'surname': 'name',
    }

    Proofing version history:
    2024v1 - inital deployment
    """

    # unique identifier
    user_id: str
    # transaction id
    transaction_id: str
    # document type
    document_type: str
    # document number
    document_number: str
    # Proofing method name
    proofing_method: str = IdentityProofingMethod.FREJA_EID.value


class FrejaEIDForeignProofing(ForeignIdProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'freja_eid',
        'proofing_version': '2024v1',
        'user_id': 'unique identifier for the user',
        'document_type': 'type of document used for identification',
        'document_number': 'document number',
        'issuing_country': 'country of issuance',
    }
    """

    # unique identifier
    user_id: str
    # transaction id
    transaction_id: str
    # document administrative number
    administrative_number: Optional[str]
    # document type (standardized english)
    document_type: str
    # document number
    document_number: str
    # issuing country
    issuing_country: str
    # Proofing method name
    proofing_method: str = IdentityProofingMethod.FREJA_EID.value


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
        'given_name': 'name',
        'surname': 'name',
    }
    """

    # Data used to initialize the vetting process
    key_id: str
    # Proofing method name
    proofing_method: str = "swedenconnect"


class MFATokenEIDASProofing(SwedenConnectEIDASProofing):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'swedenconnect',
        'proofing_version': '2022v1',
        'issuer': 'provider who performed the vetting',
        'authn_context_class': 'the asserted authn context class',
        'prid': 'Sweden connect provisional identifier',
        'prid_persistence': 'prid persistence indicator',
        'eidas_person_identifier': 'eIDAS uniqueness identifier for natural persons',
        'transaction_identifier': 'transaction id',
        'mapped_personal_identity_number': 'mapped nin',
        'personal_identity_number_binding': 'how nin is mapped'
        'key_id: 'Key id of token vetted',
    }
    """

    # Data used to initialize the vetting process
    key_id: str
    # Proofing method name
    proofing_method: str = "swedenconnect"


class MFATokenBankIDProofing(BankIDProofing):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'bankid',
        'proofing_version': '2023v1',
        'nin': 'national_identity_number',
        'given_name': 'name',
        'surname': 'name',
        'transaction_id': 'transaction id',
        'key_id: 'Key id of token vetted',
    }
    """

    # Data used to initialize the vetting process
    key_id: str


class NameUpdateProofing(NinNavetProofingLogElement):
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
    proofing_method: str = "Navet name update"


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
        'ladok_name': 'university abbreviation'
    }
    """

    nin: str
    # Ladok persistent external user id
    external_id: str
    # University name short name in Ladok
    ladok_name: str
    proofing_method: str = "eduid_ladok"


class WebauthnMfaCapabilityProofingLog(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': utc_now(),
        'created_by': 'application',
        'proofing_method': 'webauthn metadata',
        'proofing_version': '2022v1',
        'authenticator_id': UUID or certificate key identifier
        'attestation_format: fido_mds.AttestationFormat
        'user_verification_methods': []
        'key_protection': []
    }
    """

    authenticator_id: Union[UUID, str]
    attestation_format: AttestationFormat
    user_verification_methods: list[str]
    key_protection: list[str]


class FidoMetadataLogElement(LogElement):
    authenticator_id: Union[UUID, str]
    last_status_change: datetime
    metadata_entry: FidoMetadataEntry


class UserChangeLogElement(LogElement):
    eppn: str = Field(alias="eduPersonPrincipalName")
    diff: str
    log_element_id: Optional[bson.ObjectId] = Field(alias="_id", default=None)
    reason: Reason
    source: Source


class ManagedAccountLogElement(LogElement):
    """
    {
        'eduPersonPrincipalName': managed account eppn,
        'created_ts': utc_now(),
        'created_by': 'application,
        'action': 'action taken',
        'action_by': eppn,
        'expire_at': datetime,
        'data_owner': str
    }
    """

    eppn: str = Field(alias="eduPersonPrincipalName")
    action: str
    action_by: str
    expire_at: datetime
    data_owner: str
