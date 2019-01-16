# -*- coding: utf-8 -*-

from __future__ import absolute_import

from copy import deepcopy
from flask import current_app
import eduid_msg.celery
from celery.exceptions import TimeoutError
from eduid_msg.tasks import send_message as _send_message
from eduid_msg.tasks import get_postal_address as _get_postal_address
from eduid_msg.tasks import get_relations_to as _get_relations_to
from eduid_msg.tasks import sendsms as _sendsms
from eduid_msg.tasks import pong as _pong
from eduid_common.api.exceptions import MsgTaskFailed

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


def init_relay(app):
    config = deepcopy(app.config['CELERY_CONFIG'])
    config['broker_url'] = app.config['MSG_BROKER_URL']
    eduid_msg.celery.celery.conf.update(config)
    app.msg_relay = MsgRelay()
    return app


class MsgRelay(object):

    def get_language(self, lang):
        return LANGUAGE_MAPPING.get(lang, 'en_US')

    def get_postal_address(self, nin, timeout=4):
        """
        :param nin: Swedish national identity number
        :param timeout: Max wait time for task to finish
        :type nin: string
        :type timeout: int
        :return: Official name and postal address
        :rtype: OrderedDict|None

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
        rtask = _get_postal_address.apply_async(args=[nin])
        try:
            rtask.wait(timeout=timeout)
        except TimeoutError:
            raise MsgTaskFailed('get_postal_address task timed out')

        if rtask.successful():
            return rtask.get()
        else:
            raise MsgTaskFailed('get_postal_address task failed: {}'.format(rtask.get(propagate=False)))

    def get_relations_to(self, nin, relative_nin, timeout=4):
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
        :type nin: str | unicode
        :type relative_nin: str | unicode
        :type timeout: int
        :return: List of codes. Empty list if the NINs are not related.
        :rtype: [str | unicode]
        """
        rtask = _get_relations_to.apply_async(args=[nin, relative_nin])
        try:
            rtask.wait(timeout=timeout)
        except TimeoutError:
            raise MsgTaskFailed('get_relations_to task timed out')

        if rtask.successful():
            return rtask.get()
        else:
            raise MsgTaskFailed('get_relations_to task failed: {}'.format(rtask.get(propagate=False)))

    def phone_validator(self, reference, targetphone, code, language, template_name='mobile-validator'):
        """
            The template keywords are:
                * sitename: (eduID by default)
                * sitelink: (the url dashboard in personal workmode)
                * code: the verification code
                * phonenumber: the phone number to verificate
        """
        content = {
            'sitename': current_app.config.get('EDUID_SITE_NAME'),
            'sitelink': current_app.config.get('VALIDATION_URL'),
            'code': code,
            'phonenumber': targetphone,
        }
        lang = self.get_language(language)
        template = TEMPLATES_RELATION.get(template_name)

        current_app.logger.debug("SENT mobile validator message code: {0} phone number: {1} with reference {2}".format(
            code, targetphone, reference))

        try:
            res = _send_message.delay('sms', reference, content, targetphone, template, lang)
        except Exception as e:
            raise MsgTaskFailed('phone_validator task failed: {!r}'.format(e))

        current_app.logger.debug("Extra debug: Send message result: {!r}, parameters:\n{!r}".format(
            res, ['sms', reference, content, targetphone, template, lang]))

    def sendsms(self, recipient, message, reference, max_retry_seconds=86400):
        """
        :param recipient: the recipient of the sms
        :param message: message as a string (160 chars per sms)
        :param reference: Audit reference to help cross reference audit log and events
        :param max_retry_seconds: Do not retry this task if seconds trying exceeds this number

        :type recipient: six.string_types
        :type message: six.string_types
        :type reference: six.string_types
        :type max_retry_seconds: int
        """
        current_app.logger.info('Trying to send SMS with reference: {}'.format(reference))
        current_app.logger.debug(u'Recipient: {}. Message: {}'.format(recipient, message))
        try:
            res = _sendsms.delay(recipient, message, reference, max_retry_seconds)
        except Exception as e:
            raise MsgTaskFailed('sendsms task failed: {!r}'.format(e))
        current_app.logger.info('SMS with reference {} sent. Task result: {}'.format(reference, res))

    def ping(self):
        rtask = _pong.delay()
        result = rtask.get(timeout=1)
        return result
