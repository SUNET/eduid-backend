import logging
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

import eduid.workers.msg
from eduid.common.config.base import MsgConfigMixin
from eduid.common.rpc.exceptions import MsgTaskFailed, NoAddressFound, NoNavetData, NoRelationsFound

__author__ = "lundberg"

logger = logging.getLogger(__name__)


TEMPLATES_RELATION = {
    "mobile-validator": "mobile-confirm",
    "mobile-reset-password": "mobile-reset-password",
    "nin-validator": "nin-confirm",
    "nin-reset-password": "nin-reset-password",
}

LANGUAGE_MAPPING = {
    "en": "en_US",
    "sv": "sv_SE",
}


class NavetModelConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class CaseInformation(NavetModelConfig):
    last_changed: str = Field(alias="lastChanged")


class Name(NavetModelConfig):
    given_name_marking: Optional[str] = Field(default=None, alias="GivenNameMarking")
    given_name: Optional[str] = Field(default=None, alias="GivenName")
    middle_name: Optional[str] = Field(default=None, alias="MiddleName")
    surname: Optional[str] = Field(default=None, alias="Surname")
    notification_name: Optional[str] = Field(default=None, alias="NotificationName")


class RelationName(NavetModelConfig):
    given_name_marking: Optional[str] = Field(default=None, alias="GivenNameMarking")
    given_name: Optional[str] = Field(default=None, alias="GivenName")
    middle_name: Optional[str] = Field(default=None, alias="MiddleName")
    surname: Optional[str] = Field(default=None, alias="Surname")
    notification_name: Optional[str] = Field(default=None, alias="NotificationName")


class PersonId(NavetModelConfig):
    national_identity_number: Optional[str] = Field(default=None, alias="NationalIdentityNumber")
    co_ordination_number: Optional[str] = Field(default=None, alias="CoOrdinationNumber")


class OfficialAddress(NavetModelConfig):
    care_of: Optional[str] = Field(default=None, alias="CareOf")
    # From Skatteverket's documentation it is not clear why Address1
    # is needed. In practice, it is rarely used, but when actually
    # used it has been seen to often contains apartment numbers.
    address1: Optional[str] = Field(default=None, alias="Address1")
    address2: Optional[str] = Field(default=None, alias="Address2")
    postal_code: Optional[str] = Field(default=None, alias="PostalCode")
    city: Optional[str] = Field(default=None, alias="City")


class RelationId(NavetModelConfig):
    national_identity_number: Optional[str] = Field(default=None, alias="NationalIdentityNumber")
    birth_time_number: Optional[str] = Field(default=None, alias="BirthTimeNumber")


class RelationType(str, Enum):
    CHILD = "B"
    MOTHER = "MO"
    FATHER = "FA"
    PARENT = "F"
    GUARDIAN = "V"
    GUARDIAN_FOR = "VF"
    SPOUSE = "M"
    PARTNER = "P"


class Relation(NavetModelConfig):
    name: RelationName = Field(default_factory=RelationName, alias="Name")
    relation_id: RelationId = Field(alias="RelationId")
    relation_type: Optional[RelationType] = Field(default=None, alias="RelationType")
    relation_start_date: Optional[str] = Field(default=None, alias="RelationStartDate")
    relation_end_date: Optional[str] = Field(default=None, alias="RelationEndDate")
    status: Optional[str] = Field(default=None, alias="Status")


class PostalAddresses(NavetModelConfig):
    official_address: OfficialAddress = Field(alias="OfficialAddress")


class DeregisteredCauseCode(str, Enum):
    DECEASED = "AV"
    EMIGRATED = "UV"
    OLD_NIN = "GN"
    OLD_COORDINATION_NUMBER = "GS"
    # From 2006-09-20
    MISSING = "OB"
    TECHNICALLY_DEREGISTERED = "TA"
    ANNULLED_COORDINATION_NUMBER = "AS"
    # Before 2006-09-20
    OTHER_REASON = "AN"
    # From 2018-07-01
    FALSE_IDENTITY = "FI"


class DeregistrationInformation(NavetModelConfig):
    date: Optional[str] = None
    cause_code: Optional[DeregisteredCauseCode] = Field(default=None, alias="causeCode")


class Person(NavetModelConfig):
    name: Name = Field(default_factory=Name, alias="Name")
    person_id: PersonId = Field(alias="PersonId")
    deregistration_information: DeregistrationInformation = Field(alias="DeregistrationInformation")
    reference_national_identity_number: Optional[str] = Field(default=None, alias="ReferenceNationalIdentityNumber")
    postal_addresses: PostalAddresses = Field(alias="PostalAddresses")
    relations: list[Relation] = Field(default_factory=list, alias="Relations")

    def is_deregistered(self) -> bool:
        return bool(self.deregistration_information.cause_code or self.deregistration_information.date)


class NavetData(NavetModelConfig):
    case_information: CaseInformation = Field(alias="CaseInformation")
    person: Person = Field(alias="Person")


# Used to parse data from get_postal_address
class FullPostalAddress(NavetModelConfig):
    name: Name = Field(default_factory=Name, alias="Name")
    official_address: OfficialAddress = Field(default_factory=OfficialAddress, alias="OfficialAddress")


class MsgRelay:
    """
    This is the interface to the RPC task to fetch data from NAVET, and to send SMSs.
    """

    def __init__(self, config: MsgConfigMixin):
        self.app_name = config.app_name
        self.conf = config
        eduid.workers.msg.init_app(config.celery)
        # these have to be imported _after_ eduid.workers.msg.init_app()
        from eduid.workers.msg.tasks import get_all_navet_data, get_postal_address, get_relations_to, pong, sendsms

        self._get_all_navet_data = get_all_navet_data
        self._get_postal_address = get_postal_address
        self._get_relations_to = get_relations_to
        self._send_sms = sendsms
        self._pong = pong

    @staticmethod
    def get_language(lang: str) -> str:
        return LANGUAGE_MAPPING.get(lang, "en_US")

    def get_all_navet_data(self, nin: str, timeout: int = 25, allow_deregistered: bool = False) -> NavetData:
        """
        :param nin: Swedish national identity number
        :param timeout: Max wait time for task to finish
        :param allow_deregistered: allow return of deregistered persons
        :return: All Navet data about the person
        """
        rtask = self._get_all_navet_data.apply_async(args=[nin])
        try:
            ret = rtask.get(timeout=timeout)
        except Exception as e:
            rtask.forget()
            raise MsgTaskFailed(f"get_all_navet_data task failed: {e}")

        if ret is None:
            raise NoNavetData("No data returned from Navet")

        try:
            data = NavetData.model_validate(ret)
        except ValidationError:
            logger.exception("Insufficient data returned from Navet")
            raise NoNavetData("Insufficient data returned from Navet")

        if not data.person.is_deregistered() or allow_deregistered:
            return data
        raise NoNavetData("No data returned from Navet")

    def get_postal_address(self, nin: str, timeout: int = 25) -> FullPostalAddress:
        """
        :param nin: Swedish national identity number
        :param timeout: Max wait time for task to finish
        :return: Official name and postal address

            The data format from worker is:

                OrderedDict([
                    (u'Name', OrderedDict([
                        (u'GivenNameMarking', u'20'),
                        (u'GivenName', u'personal name'),
                        (u'SurName', u'thesurname')
                    ])),
                    (u'OfficialAddress', OrderedDict([
                        (u'Address2', u'StreetName 103'),
                        (u'PostalCode', u'74141'),
                        (u'City', u'STOCKHOLM')
                    ]))
                ])
        """
        rtask = self._get_postal_address.apply_async(args=[nin])
        try:
            ret = rtask.get(timeout=timeout)
        except Exception as e:
            rtask.forget()
            raise MsgTaskFailed(f"get_postal_address task failed: {e}")

        if ret is None:
            raise NoAddressFound("No postal address returned from Navet")

        try:
            data = FullPostalAddress.model_validate(ret)
            return data
        except ValidationError:
            logger.exception("Missing data in postal address returned from Navet")
            raise NoAddressFound("Missing data in postal address returned from Navet")

    def get_relations_to(self, nin: str, relative_nin: str, timeout: int = 25) -> list[RelationType]:
        """
        Get a list of the NAVET 'Relations' type codes between a NIN and a relatives NIN.

        Known codes:
            M = spouse (make/maka)
            B = child (barn)
            FA = father
            MO = mother
            VF = some kind of legal guardian status. Children typically have ['B', 'VF'] it seems.

        :param nin: Swedish National Identity Number
        :param relative_nin: Another Swedish National Identity Number
        :param timeout: Max wait time for task to finish
        :return: List of codes. Empty list if the NINs are not related.
        """
        rtask = self._get_relations_to.apply_async(args=[nin, relative_nin])
        try:
            ret = rtask.get(timeout=timeout)
        except Exception as e:
            rtask.forget()
            raise MsgTaskFailed(f"get_relations_to task failed: {e}")

        if ret is not None:
            return [RelationType(item) for item in ret]
        raise NoRelationsFound("No relations returned from Navet")

    def sendsms(self, recipient: str, message: str, reference: str, timeout: int = 25) -> None:
        """
        :param recipient: the recipient of the sms
        :param message: message as a string (160 chars per sms)
        :param reference: Audit reference to help cross reference audit log and events
        :param timeout: Max wait time for task to finish
        """
        logger.info(f"Trying to send SMS with reference: {reference}")
        logger.debug(f"Recipient: {recipient}. Message: {message}")
        rtask = self._send_sms.apply_async(args=[recipient, message, reference])

        try:
            res = rtask.get(timeout=timeout)
            logger.info(f"SMS with reference {reference} sent. Task result: {res}")
        except Exception as e:
            rtask.forget()
            raise MsgTaskFailed(f"sendsms task failed: {repr(e)}")

    def ping(self, timeout: int = 1) -> str:
        """
        Check if this application is able to reach an Msg worker.
        :return: Result of celery Task.get
        """
        rtask = self._pong.apply_async(kwargs={"app_name": self.app_name})
        try:
            return rtask.get(timeout=timeout)
        except Exception as e:
            rtask.forget()
            raise MsgTaskFailed(f"ping task failed: {repr(e)}")
