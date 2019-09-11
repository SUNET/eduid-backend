# -*- coding: utf-8 -*-

import eduid_am
from flask import Flask, current_app

from eduid_common.api.exceptions import AmTaskFailed
from eduid_userdb import User
from eduid_userdb.exceptions import LockedIdentityViolation

__author__ = 'lundberg'


def init_relay(app: Flask, application_name: str) -> Flask:
    """
    :param app: Flask app
    :param application_name: Name to help am find the entry point for the am plugin
    :return: Flask app
    """
    app.am_relay = AmRelay(app.config['CELERY_CONFIG'], application_name)
    return app


class AmRelay(object):

    def __init__(self, config: dict, relay_for: str):
        """
        :param config: celery config
        :param relay_for: Name of application to relay for
        """
        self.relay_for = relay_for

        eduid_am.init_app(config)
        # these have to be imported _after_ eduid_am.init_app()
        from eduid_am.tasks import update_attributes_keep_result, pong
        self._update_attrs = update_attributes_keep_result
        self._pong = pong

    def request_user_sync(self, user: User, timeout: int = 4) -> bool:
        """
        Use Celery to ask eduid-am worker to propagate changes from our
        private UserDB into the central UserDB.

        :param user: User object
        :param timeout: Max wait time for task to finish

        :return: True if successful
        """
        # XXX: Do we need to check for acceptable_user_types?
        try:
            user_id = str(user.user_id)
        except (AttributeError, ValueError) as e:
            current_app.logger.error(f'Bad user_id in sync request: {e}')
            raise ValueError('Missing user_id. Can only propagate changes for eduid_userdb.User users.')

        current_app.logger.debug(f"Asking Attribute Manager to sync user {user}")
        rtask = self._update_attrs.delay(self.relay_for, user_id)
        try:
            result = rtask.get(timeout=timeout)
            current_app.logger.debug(f"Attribute Manager sync result: {result} for user {user}")
            return result
        except LockedIdentityViolation as e:
            rtask.forget()
            raise e
        except Exception as e:
            rtask.forget()
            raise AmTaskFailed(f'request_user_sync task failed: {e}')

    def ping(self, timeout: int = 1) -> str:
        """
        Check if this application is able to reach an AM worker.
        :return: Result of celery Task.get
        """
        rtask = self._pong.delay(self.relay_for)
        result = rtask.get(timeout=timeout)
        return result
