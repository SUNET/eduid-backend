# -*- coding: utf-8 -*-

from __future__ import absolute_import

from copy import deepcopy
from flask import current_app
import eduid_am
from eduid_common.api.exceptions import AmTaskFailed

__author__ = 'lundberg'


def init_relay(app, application_name):
    """
    :param app: Flask app
    :type app: flask.Flask
    :param application_name: Name to help am find the entry point for the am plugin
    :type application_name: str|unicode
    :return: Flask app
    :rtype: flask.Flask
    """
    config = deepcopy(app.config['CELERY_CONFIG'])
    config['broker_url'] = app.config['AM_BROKER_URL']
    config['result_backend'] = config['broker_url']
    app.am_relay = AmRelay(config, application_name)
    return app


class AmRelay(object):

    def __init__(self, config, relay_for):
        """
        :param config: celery config
        :type config: dict
        :param relay_for: Name of application to relay for
        :type relay_for: str|unicode
        """
        self.relay_for = relay_for

        eduid_am.init_app(config)
        # these have to be imported _after_ eduid_am.init_app()
        from eduid_am.tasks import update_attributes_keep_result, pong
        self._update_attrs = update_attributes_keep_result
        self._pong = pong

    def request_user_sync(self, user):
        """
        Use Celery to ask eduid-am worker to propagate changes from our
        private UserDB into the central UserDB.

        :param user: User object
        :type user: eduid_userdb.User

        :return: Result of celery Task.get()
        """
        # XXX: Do we need to check for acceptable_user_types?
        try:
            user_id = str(user.user_id)
        except (AttributeError, ValueError) as e:
            current_app.logger.error('Bad user_id in sync request: {!s}'.format(e))
            raise ValueError('Missing user_id. Can only propagate changes for eduid_userdb.User users.')

        current_app.logger.debug("Asking Attribute Manager to sync user {!s}".format(user))
        try:
            rtask = self._update_attrs.delay(self.relay_for, user_id)
            result = rtask.get(timeout=3)
            current_app.logger.debug("Attribute Manager sync result: {!r} for user {!s}".format(result, user))
            return result
        except Exception as e:
            current_app.logger.exception("Exception: {!s}".format(e))
            current_app.logger.exception(
                "Failed Attribute Manager sync request for user {!s}. trying again".format(user))
            try:
                rtask = self._update_attrs.delay(self.relay_for, user_id)
                result = rtask.get(timeout=7)
                current_app.logger.debug("Attribute Manager sync result: {!r} for user {!s}".format(result, user))
                return result
            except Exception as e:
                current_app.logger.exception("Failed Attribute Manager sync request retry for user {!s}".format(user))
                raise AmTaskFailed('request_user_sync task failed: {}'.format(e))

    def ping(self):
        """
        Check if this application is able to reach an AM worker.
        :return: Result of celery Task.get
        """
        rtask = self._pong.delay(self.relay_for)
        result = rtask.get(timeout=2)
        return result
