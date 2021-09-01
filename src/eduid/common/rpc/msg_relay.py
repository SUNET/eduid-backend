# -*- coding: utf-8 -*-
import logging
from typing import List, Optional

from pydantic import BaseModel, Extra, Field

import eduid.workers.msg
from eduid.common.config.base import MsgConfigMixin
from eduid.webapp.common.api.exceptions import MsgTaskFailed

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


TEMPLATES_RELATION = {
    'mobile-validator': 'mobile-confirm',
    'mobile-reset-password': 'mobile-reset-password',
    'nin-validator': 'nin-confirm',
    'nin-reset-password': 'nin-reset-password',
}

LANGUAGE_MAPPING = {
    'en': 'en_US',
    'sv': 'sv_SE',
}


class NavetModelConfig(BaseModel):
    class Config:
        allow_population_by_field_name = True


class CaseInformation(NavetModelConfig):
    last_changed: str = Field(alias='lastChanged')


class Name(NavetModelConfig):
    given_name_marking: Optional[str] = Field(default=None, alias='GivenNameMarking')
    given_name: Optional[str] = Field(default=None, alias='GivenName')
    middle_name: Optional[str] = Field(default=None, alias='MiddleName')
    surname: Optional[str] = Field(default=None, alias='Surname')


class PersonId(NavetModelConfig):
    national_identity_number: Optional[str] = Field(default=None, alias='NationalIdentityNumber')
    co_ordination_number: Optional[str] = Field(default=None, alias='CoOrdinationNumber')


class OfficialAddress(NavetModelConfig):
    care_of: Optional[str] = Field(default=None, alias='CareOf')
    # From Skatteverket's documentation it is not clear why Address1
    # is needed. In practice it is rarely used, but when actually
    # used it has been seen to often contains apartment numbers.
    address1: Optional[str] = Field(default=None, alias='Address1')
    address2: Optional[str] = Field(default=None, alias='Address2')
    postal_code: Optional[str] = Field(default=None, alias='PostalCode')
    city: Optional[str] = Field(default=None, alias='City')


class RelationId(NavetModelConfig):
    national_identity_number: Optional[str] = Field(default=None, alias='NationalIdentityNumber')
    birth_time_number: Optional[str] = Field(default=None, alias='BirthTimeNumber')


class Relation(NavetModelConfig):
    name: Name = Field(default_factory=Name, alias='Name')
    relation_id: RelationId = Field(alias='RelationId')
    relation_type: Optional[str] = Field(default=None, alias='RelationType')
    relation_start_date: Optional[str] = Field(default=None, alias='RelationStartDate')
    relation_end_date: Optional[str] = Field(default=None, alias='RelationEndDate')
    status: Optional[str] = Field(default=None, alias='Status')


class Relations(NavetModelConfig):
    relation: List[Relation] = Field(default_factory=list, alias='Relation')


class Person(NavetModelConfig):
    name: Name = Field(default_factory=Name, alias='Name')
    person_id: PersonId = Field(alias='PersonId')
    reference_national_identity_number: Optional[str] = Field(default=None, alias='ReferenceNationalIdentityNumber')
    official_address: OfficialAddress = Field(alias='OfficialAddress')
    relations: Relations = Field(alias='Relations')


class NavetData(NavetModelConfig):
    case_information: CaseInformation = Field(alias='CaseInformation')
    person: Person = Field(alias='Person')


class MsgRelay(object):
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
        return LANGUAGE_MAPPING.get(lang, 'en_US')

    def get_all_navet_data(self, nin: str, timeout: int = 25) -> NavetData:
        """
        :param nin: Swedish national identity number
        :param timeout: Max wait time for task to finish
        :return: All Navet data about the person
        """
        rtask = self._get_all_navet_data.apply_async(args=[nin])
        try:
            ret = rtask.get(timeout=timeout)
            if ret is not None:
                return NavetData.parse_obj(ret)
            raise MsgTaskFailed('No data returned from Navet')
        except Exception as e:
            rtask.forget()
            raise MsgTaskFailed(f'get_all_navet_data task failed: {e}')

    def get_postal_address(self, nin: str, timeout: int = 25) -> dict:
        """
        :param nin: Swedish national identity number
        :param timeout: Max wait time for task to finish
        :return: Official name and postal address

            The expected address format is:

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
            if ret is not None:
                return ret
            raise MsgTaskFailed('No postal address returned from Navet')
        except Exception as e:
            rtask.forget()
            raise MsgTaskFailed(f'get_postal_address task failed: {e}')

    def get_relations_to(self, nin: str, relative_nin: str, timeout: int = 25) -> List[str]:
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
            if ret is not None:
                return ret
            raise MsgTaskFailed('No postal address returned from Navet')
        except Exception as e:
            rtask.forget()
            raise MsgTaskFailed(f'get_relations_to task failed: {e}')

    def sendsms(self, recipient: str, message: str, reference: str, timeout: int = 25) -> None:
        """
        :param recipient: the recipient of the sms
        :param message: message as a string (160 chars per sms)
        :param reference: Audit reference to help cross reference audit log and events
        :param timeout: Max wait time for task to finish
        """
        logger.info(f'Trying to send SMS with reference: {reference}')
        logger.debug(f'Recipient: {recipient}. Message: {message}')
        rtask = self._send_sms.apply_async(args=[recipient, message, reference])

        try:
            res = rtask.get(timeout=timeout)
            logger.info(f'SMS with reference {reference} sent. Task result: {res}')
        except Exception as e:
            rtask.forget()
            raise MsgTaskFailed(f'sendsms task failed: {repr(e)}')

    def ping(self, timeout: int = 1) -> str:
        """
        Check if this application is able to reach an Msg worker.
        :return: Result of celery Task.get
        """
        rtask = self._pong.apply_async(kwargs={'app_name': self.app_name})
        try:
            return rtask.get(timeout=timeout)
        except Exception as e:
            rtask.forget()
            raise MsgTaskFailed(f'ping task failed: {repr(e)}')
