# -*- coding: utf-8 -*-
import logging
from typing import List

import eduid.workers.msg

from eduid.common.api.exceptions import MsgTaskFailed
from eduid.common.config.base import MsgConfigMixin

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


class MsgRelay(object):
    def __init__(self, config: MsgConfigMixin):
        self.conf = config
        eduid.workers.msg.init_app(config.celery)
        # these have to be imported _after_ eduid.workers.msg.init_app()
        from eduid.workers.msg.tasks import get_postal_address, get_relations_to, pong, sendsms

        self._get_postal_address = get_postal_address
        self._get_relations_to = get_relations_to
        self._send_sms = sendsms
        self._pong = pong

    @staticmethod
    def get_language(lang: str) -> str:
        return LANGUAGE_MAPPING.get(lang, 'en_US')

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
        rtask = self._pong.apply_async()
        try:
            return rtask.get(timeout=timeout)
        except Exception as e:
            rtask.forget()
            raise MsgTaskFailed(f'ping task failed: {repr(e)}')
