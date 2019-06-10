from __future__ import absolute_import

import bson

from celery import Task
from celery.utils.log import get_task_logger

from eduid_am.common import celery
from eduid_am.fetcher_registry import AFRegistry
from eduid_am.worker import worker_config
from eduid_userdb import UserDB
from eduid_userdb.exceptions import UserDoesNotExist, LockedIdentityViolation, ConnectionError
from eduid_am.consistency_checks import unverify_duplicates, check_locked_identity


if celery is None:
    raise RuntimeError('Must call eduid_am.init_app before importing tasks')

logger = get_task_logger(__name__)


class AttributeManager(Task):
    """Singleton that stores reusable objects like the MongoDB database
       or the attribute fetchers registry."""

    abstract = True  # This means Celery won't register this as another task

    def __init__(self):
        self.default_db_uri = worker_config.get('MONGO_URI')
        self.userdb = None
        self.init_db()
        self.init_af_registry()

    def init_db(self):
        if self.default_db_uri is not None:
            # self.userdb is the UserDB to which AM will write the updated users. This setting will
            # be None when this class is instantiated on the 'client' side (e.g. in a microservice)
            self.userdb = UserDB(self.default_db_uri, 'eduid_am', 'attributes')

    def init_af_registry(self):
        self.af_registry = AFRegistry(worker_config)

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        # The most common problem when tasks raise exceptions is that mongodb has switched master,
        # but it is hard to accurately trap the right exception without importing pymongo here so
        # let's just reload all databases (self.userdb here and the plugins databases) when we
        # get an exception
        logger.exception('Task failed. Reloading db and plugins.')
        self.init_db()
        self.init_af_registry()


@celery.task(ignore_results=True, base=AttributeManager)
def update_attributes(app_name, obj_id):
    """
    Task executing on the Celery worker service as an RPC called from
    the different eduID applications.

    :param app_name: calling application name, like 'eduid_signup'
    :param obj_id: entry in the calling applications name that has changed (object id)
    :type app_name: string
    :type obj_id: string
    """
    _update_attributes(app_name, obj_id)


@celery.task(base=AttributeManager)
def update_attributes_keep_result(app_name, obj_id):
    """
    This task is exactly the same as update_attributes, except that
    it keeps the celery results so that it can be used synchronously.

    This is called during signup, so we can tell that the account
    has been successfully created.

    :param app_name: calling application name, like 'eduid_signup'
    :param obj_id: entry in the calling applications name that has changed (object id)
    :type app_name: string
    :type obj_id: string
    """
    _update_attributes(app_name, obj_id)


def _update_attributes(app_name, obj_id):
    logger.debug('Update attributes called for {!r} by {!r}'.format(obj_id, app_name))
    try:
        return _update_attributes_safe(app_name, obj_id)
    except Exception:
        logger.error('Got exception processing {!r}[{!r}]'.format(app_name, obj_id), exc_info=True)
        raise


def _update_attributes_safe(app_name, user_id):
    self = update_attributes
    logger.debug('update {!s}[{!s}]'.format(app_name, user_id))

    try:
        attribute_fetcher = self.af_registry[app_name]
    except KeyError as error:
        logger.error('Attribute fetcher for {!s} is not installed'.format(app_name))
        raise RuntimeError(f'Missing attribute fetcher, {error}')

    logger.debug("Attribute fetcher for {!s}: {!r}".format(app_name, attribute_fetcher))

    try:
        _id = bson.ObjectId(user_id)
    except bson.errors.InvalidId:
        logger.error('Invalid user_id {!s} from app {!s}'.format(user_id, app_name))
        raise ValueError('Bad user_id')

    try:
        attributes = attribute_fetcher.fetch_attrs(_id)
    except UserDoesNotExist as error:
        logger.error('The user {!s} does not exist in the database for plugin {!s}: {!s}'.format(
            _id, app_name, error))
        return
    except ValueError as error:
        logger.error(f'Error syncing user {_id}:  {error}')
        return

    try:
        logger.debug('Checking locked identity during sync attempt from {}'.format(app_name))
        attributes = check_locked_identity(self.userdb, _id, attributes, app_name)
    except LockedIdentityViolation as e:
        logger.error(e)
        return

    # TODO: Update mongodb to >3.2 (partial index support) so we can optimistically update a user and run this check
    # TODO: if the update fails
    logger.debug('Checking other users for already verified elements during sync attempt from {}'.format(app_name))
    unverify_duplicates(self.userdb, _id, attributes)

    logger.debug('Attributes fetched from app {!s} for user {!s}: {!s}'.format(app_name, user_id, attributes))
    self.userdb.update_user(_id, attributes)


@celery.task(base=AttributeManager)
def pong(app_name):
    if pong.default_db_uri and pong.userdb.is_healthy():
        return 'pong for {}'.format(app_name)
    raise ConnectionError('Database not healthy')
