# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import current_app
import eduid_am.celery
from eduid_am.tasks import update_attributes_keep_result

__author__ = 'lundberg'


def init_relay(app, application_name, acceptable_user_types):
    """
    :param app: Flask app
    :type app:
    :param application_name: Name to help am find the entry point for the am plugin
    :type application_name: str|unicode
    :param acceptable_user_types: User types to try to sync
    :type acceptable_user_types: tuple
    :return: Flask app
    :rtype:
    """
    config = app.config['CELERY_CONFIG']
    config['BROKER_URL'] = app.config['AM_BROKER_URL']
    eduid_am.celery.celery.conf.update(config)
    app.am_relay = AmRelay(relay_for=application_name, acceptable_user_types=acceptable_user_types)
    return app


class AmRelay(object):

    def __init__(self, relay_for, acceptable_user_types):
        """
        :param relay_for: Name of application to relay for
        :type relay_for: str|unicode
        :param acceptable_user_types: User types to try and sync
        :type acceptable_user_types: tuple
        """
        self.relay_for = relay_for
        self.acceptable_user_types = acceptable_user_types

    def request_sync(self, user):
        """
        Use Celery to ask eduid-am worker to propagate changes from our
        private UserDB into the central UserDB.

        :param user: User object
        :type user: any(self.acceptable_user_types)

        :return:
        """
        # XXX: Do we need to check for acceptable_user_types?
        if isinstance(user, self.acceptable_user_types):
            user_id = str(user.user_id)
        else:
            raise ValueError('Can only propagate changes for {!s}.'.format(self.acceptable_user_types))

        current_app.logger.debug("Asking Attribute Manager to sync user {!s}".format(user))
        try:
            rtask = update_attributes_keep_result.delay(self.relay_for, user_id)
            result = rtask.get(timeout=3)
            current_app.logger.debug("Attribute Manager sync result: {!r}".format(result))
            return result
        except Exception as e:
            current_app.logger.exception("Exception: {!s}".format(e))
            current_app.logger.exception("Failed Attribute Manager sync request. trying again")
            try:
                rtask = update_attributes_keep_result.delay(self.relay_for, user_id)
                result = rtask.get(timeout=7)
                current_app.logger.debug("Attribute Manager sync result: {!r}".format(result))
                return result
            except Exception as e:
                current_app.logger.exception("Failed Attribute Manager sync request retry")
                raise e
