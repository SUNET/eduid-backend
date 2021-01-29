# -*- coding: utf-8 -*-
import warnings
from typing import List, Optional

from flask import current_app

import eduid_msg

from eduid_common.api.app import EduIDBaseApp
from eduid_common.api.exceptions import MsgTaskFailed
from eduid_common.config.base import CeleryConfig

__author__ = 'lundberg'

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


def init_relay(app: EduIDBaseApp) -> None:
    """
    :param app: Flask app
    """
    app.msg_relay = MsgRelay(app.config.celery_config)
    return None


class MsgRelay(object):
    def __init__(self, settings: CeleryConfig):
        eduid_msg.init_app(settings)
        # these have to be imported _after_ eduid_am.init_app()
        from eduid_msg.tasks import get_postal_address, get_relations_to, pong, send_message, sendsms

        self._get_postal_address = get_postal_address
        self._get_relations_to = get_relations_to
        self._send_message = send_message
        self._send_sms = sendsms
        self._pong = pong

    @staticmethod
    def get_language(lang: str) -> str:
        return LANGUAGE_MAPPING.get(lang, 'en_US')

    def get_postal_address(self, nin: str, timeout: int = 25) -> Optional[dict]:
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
            VF = some kind of legal guardian status. Childs typically have ['B', 'VF'] it seems.

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

    def phone_validator(
        self,
        reference: str,
        targetphone: str,
        code: str,
        language: str,
        template_name: str = 'mobile-validator',
        timeout: int = 25,
    ) -> None:
        """
            The template keywords are:
                * sitename: (eduID by default)
                * sitelink: (the url dashboard)
                * code: the verification code
                * phonenumber: the phone number to verify
        """
        warnings.warn("This function will be removed. Use sendsms instead.", DeprecationWarning)
        current_app.logger.info('Trying to send phone validation SMS with reference: {}'.format(reference))
        content = {
            'sitename': current_app.config.get('EDUID_SITE_NAME'),
            'sitelink': current_app.config.get('VALIDATION_URL'),
            'code': code,
            'phonenumber': targetphone,
        }
        lang = self.get_language(language)
        template = TEMPLATES_RELATION.get(template_name)

        rtask = self._send_message.apply_async(args=['sms', reference, content, targetphone, template, lang])
        try:
            res = rtask.get(timeout=timeout)
            current_app.logger.debug(
                f"SENT mobile validator message code: {code} phone number: {targetphone} with reference {reference}"
            )
            current_app.logger.debug(
                f"Extra debug: Send message result: {repr(res)},"
                f" parameters:\n{repr(['sms', reference, content, targetphone, template, lang])}"
            )
        except Exception as e:
            rtask.forget()
            raise MsgTaskFailed(f'phone_validator task failed: {e}')

    def sendsms(self, recipient: str, message: str, reference: str, timeout: int = 25) -> None:
        """
        :param recipient: the recipient of the sms
        :param message: message as a string (160 chars per sms)
        :param reference: Audit reference to help cross reference audit log and events
        :param timeout: Max wait time for task to finish
        """
        current_app.logger.info('Trying to send SMS with reference: {}'.format(reference))
        current_app.logger.debug(u'Recipient: {}. Message: {}'.format(recipient, message))
        rtask = self._send_sms.apply_async(args=[recipient, message, reference])

        try:
            res = rtask.get(timeout=timeout)
            current_app.logger.info('SMS with reference {} sent. Task result: {}'.format(reference, res))
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
