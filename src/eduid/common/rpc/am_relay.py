import logging

import eduid.workers.am
from eduid.common.config.base import AmConfigMixin
from eduid.common.rpc.exceptions import AmTaskFailed
from eduid.userdb import User
from eduid.userdb.exceptions import LockedIdentityViolation

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class AmRelay:
    """
    This is the interface to the RPC task to save users to the central userdb.
    """

    def __init__(self, config: AmConfigMixin):
        """
        :param config: celery config
        :param relay_for: Name of application to relay for
        """
        self.app_name = f"eduid_{config.app_name}"
        if config.am_relay_for_override is not None:
            self.app_name = config.am_relay_for_override

        eduid.workers.am.init_app(config.celery)
        # these have to be imported _after_ eduid.workers.am.init_app()
        from eduid.workers.am.tasks import pong, update_attributes_keep_result

        self._update_attrs = update_attributes_keep_result
        self._pong = pong

    def request_user_sync(self, user: User, timeout: int = 25, app_name_override: str | None = None) -> bool:
        """
        Use Celery to ask eduid-am worker to propagate changes from our
        private UserDB into the central UserDB.

        :param user: User object
        :param timeout: Max wait time for task to finish
        :param app_name_override: Used in tests to 'spoof' sync requests.

        :return: True if successful
        """
        # XXX: Do we need to check for acceptable_user_types?
        try:
            user_id = str(user.user_id)
        except (AttributeError, ValueError) as e:
            logger.error(f"Bad user_id in sync request: {e}")
            raise ValueError("Missing user_id. Can only propagate changes for eduid.userdb.User users.")

        _app_name = self.app_name
        if app_name_override:
            _app_name = app_name_override
        logger.debug(f"Asking Attribute Manager to sync user {user} from {_app_name}")
        rtask = self._update_attrs.delay(_app_name, user_id)
        try:
            result = rtask.get(timeout=timeout)
            logger.debug(f"Attribute Manager sync result: {result} for user {user}")
            return result
        except LockedIdentityViolation as e:
            rtask.forget()
            raise e
        except Exception as e:
            rtask.forget()
            logger.exception(f"Failed Attribute Manager sync request for user {user}")
            raise AmTaskFailed(f"request_user_sync task failed: {e}")

    def ping(self, timeout: int = 1) -> str:
        """
        Check if this application is able to reach an AM worker.
        :return: Result of celery Task.get
        """
        rtask = self._pong.apply_async(kwargs={"app_name": self.app_name})
        try:
            return rtask.get(timeout=timeout)
        except Exception as e:
            rtask.forget()
            raise AmTaskFailed(f"ping task failed: {repr(e)}")
