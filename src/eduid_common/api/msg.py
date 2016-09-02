# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import current_app
import eduid_msg.celery
from eduid_msg.tasks import get_postal_address as _get_postal_address

__author__ = 'lundberg'


def init_relay(app):
    config = app.config['CELERY_CONFIG']
    config['BROKER_URL'] = app.config['MSG_BROKER_URL']
    eduid_msg.celery.celery.conf.update(config)
    app.msg_relay = MsgRelay()
    return app


class MsgRelay(object):

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

