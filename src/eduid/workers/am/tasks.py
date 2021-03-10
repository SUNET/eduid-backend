import warnings
from typing import Optional

import bson
from celery import Task
from celery.utils.log import get_task_logger

from eduid.userdb import UserDB
from eduid.userdb.exceptions import ConnectionError, LockedIdentityViolation, UserDoesNotExist
from eduid.workers.am.common import AmWorkerSingleton
from eduid.workers.am.consistency_checks import check_locked_identity, unverify_duplicates

logger = get_task_logger(__name__)

app = AmWorkerSingleton.celery


class AttributeManager(Task):
    """Singleton that stores reusable objects like the MongoDB database
       or the attribute fetchers registry."""

    abstract = True  # This means Celery won't register this as another task

    def __init__(self):
        self._userdb: Optional[UserDB] = None

    @property
    def userdb(self) -> Optional[UserDB]:
        if self._userdb:
            return self._userdb
        if AmWorkerSingleton.am_config.mongo_uri:
            # self.userdb is the UserDB to which AM will write the updated users. This setting will
            # be None when this class is instantiated on the 'client' side (e.g. in a microservice)
            self._userdb = UserDB(AmWorkerSingleton.am_config.mongo_uri, 'eduid_am', 'attributes')
        return self._userdb

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        # The most common problem when tasks raise exceptions is that mongodb has switched master,
        # but it is hard to accurately trap the right exception without importing pymongo here so
        # let's just reload all databases (self.userdb here and the plugins databases) when we
        # get an exception
        logger.exception('Task failed. Reloading db and plugins.')
        self._userdb = None
        AmWorkerSingleton.af_registry.reset()


@app.task(bind=True, ignore_results=True, base=AttributeManager)
def update_attributes(self: AttributeManager, app_name: str, user_id: str) -> None:
    """
    Task executing on the Celery worker service as an RPC called from
    the different eduID applications.

    :param self: base class
    :param app_name: calling application name, like 'eduid_signup'
    :param user_id: id for the user that has been updated by the calling application
    """
    warnings.warn("This function will be removed. Use update_attributes_keep_result instead.", DeprecationWarning)
    _update_attributes(self, app_name, user_id)


@app.task(bind=True, base=AttributeManager)
def update_attributes_keep_result(self: AttributeManager, app_name: str, user_id: str) -> bool:
    """
    This task is exactly the same as update_attributes, except that
    it keeps the celery results so that it can be used synchronously.

    :param self: base class
    :param app_name: calling application name, like 'eduid_signup'
    :param user_id: id for the user that has been updated by the calling application
    """
    return _update_attributes(self, app_name, user_id)


def _update_attributes(task: AttributeManager, app_name: str, user_id: str) -> bool:
    logger.debug(f'Update attributes called for {user_id} by {app_name}')

    try:
        attribute_fetcher = AmWorkerSingleton.af_registry.get_fetcher(app_name)
        logger.debug(f"Attribute fetcher for {app_name}: {repr(attribute_fetcher)}")
    except KeyError as e:
        logger.error(f'Attribute fetcher for {app_name} is not installed')
        raise RuntimeError(f'Missing attribute fetcher, {e}')

    try:
        _id = bson.ObjectId(user_id)
    except bson.errors.InvalidId:
        logger.error(f'Invalid user_id {user_id} from app {app_name}')
        raise ValueError('Invalid user_id')

    try:
        attributes = attribute_fetcher.fetch_attrs(_id)
    except UserDoesNotExist as e:
        logger.error(f'The user {_id} does not exist in the database for plugin {app_name}: {e}')
        raise e
    except ValueError as e:
        logger.error(f'Error syncing user {_id}:  {e}')
        raise e

    try:
        logger.debug(f'Checking locked identity during sync attempt from {app_name}')
        attributes = check_locked_identity(task.userdb, _id, attributes, app_name)
    except LockedIdentityViolation as e:
        logger.error(e)
        raise e

    # TODO: Update mongodb to >3.2 (partial index support) so we can optimistically update a user and run this check
    # TODO: if the update fails
    logger.debug(f'Checking other users for already verified elements during sync attempt from {app_name}')
    unverify_duplicates(task.userdb, _id, attributes)

    logger.debug(f'Attributes fetched from app {app_name} for user {_id}: {attributes}')
    try:
        task.userdb.update_user(_id, attributes)
    except ConnectionError as e:
        logger.error(f'update_attributes_keep_result connection error: {e}', exc_info=True)
        task.retry(default_retry_delay=1, max_retries=3, exc=e)
    return True


@app.task(bind=True, base=AttributeManager)
def pong(self, app_name):
    if self.default_db_uri and self.userdb.is_healthy():
        return f'pong for {app_name}'
    raise ConnectionError('Database not healthy')
