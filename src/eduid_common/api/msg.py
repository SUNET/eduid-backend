# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import current_app
import eduid_msg.celery
from eduid_msg.tasks import send_message as _send_message
from eduid_msg.tasks import get_postal_address as _get_postal_address
from eduid_msg.tasks import get_relations_to as _get_relations_to


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
    config = app.config['CELERY_CONFIG']
    config['BROKER_URL'] = app.config['MSG_BROKER_URL']
    eduid_msg.celery.celery.conf.update(config)
    app.msg_relay = MsgRelay()
    return app


class MsgRelay(object):

    def get_content(self):
        # site_name = current_app.config.get("site.name", "eduID")
        # site_url = current_app.config.get("site.url", "http://eduid.se")
        # return {
        #     'sitename': current_app.config['site.name'],
        #     'sitelink': current_app.config['personal_dashboard_base_url'],
        # }
        return {
            'sitename': current_app.config.get("site.name", "eduID"),
            'sitelink': current_app.config.get("site.url", "http://eduid.se"),
        }

    def get_language(self, lang):
        return LANGUAGE_MAPPING.get(lang, 'en_US')

    def get_postal_address(self, nin):
        """
        :param nin: Swedish national identity number
        :type nin: string
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
        try:
            rtask = _get_postal_address.apply_async(args=[nin])
            rtask.wait()
            if rtask.successful():
                return rtask.get()
        except Exception as e:
            current_app.logger.error('Celery task failed: {!r}'.format(e))
            raise e
        return None

    def phone_validator(self, reference, targetphone, code, language, template_name='mobile-validator'):
        """
            The template keywords are:
                * sitename: (eduID by default)
                * sitelink: (the url dashboard in personal workmode)
                * code: the verification code
                * phonenumber: the phone number to verificate
        """
        content = self.get_content()
        content.update({
            'code': code,
            'phonenumber': targetphone,
        })
        lang = self.get_language(language)
        template = TEMPLATES_RELATION.get(template_name)

        current_app.logger.debug("SENT mobile validator message code: {0}"
                                 " phone number: {1} with reference {2}".format(
                                                           code, targetphone, reference))
        res = _send_message.delay('sms', reference, content, targetphone, template, lang)

        current_app.logger.debug("Extra debug: Send message result: {!r}, parameters:\n{!r}".format(
            res, ['sms', reference, content, targetphone, template, lang]))

    def get_relations_to(self, nin, relative_nin):
        """
        Get a list of the NAVET 'Relations' type codes between a NIN and a relatives NIN.

        Known codes:
            M = spouse (make/maka)
            B = child (barn)
            FA = father
            MO = mother
            VF = some kind of legal guardian status
            F = Parent

        :param nin: Swedish National Identity Number
        :param relative_nin: Another Swedish National Identity Number
        :type nin: six.string_types
        :type relative_nin: six.string_types
        :return: List of codes. Empty list if the NINs are not related.
        :rtype: six.string_types
        """
        try:
            rtask = _get_relations_to.apply_async(args=[nin, relative_nin])
            rtask.wait()
            if rtask.successful():
                return rtask.get()
        except Exception as e:
            current_app.logger.error('Celery task failed: {!r}'.format(e))
            raise e
