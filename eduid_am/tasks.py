from __future__ import absolute_import

import sys
import bson
from importlib import import_module

from celery import Task
from celery.utils.log import get_task_logger

from pkg_resources import iter_entry_points

from eduid_am.common import celery
from eduid_am.worker import worker_config
from eduid_userdb import UserDB
from eduid_userdb.exceptions import UserDoesNotExist, LockedIdentityViolation, ConnectionError
from eduid_am.consistency_checks import unverify_duplicates, check_locked_identity


if celery is None:
    raise RuntimeError('Must call eduid_am.init_app before importing tasks')

logger = get_task_logger(__name__)


class PluginsRegistry(object):
    """
    In-memory information about existing Attribute Manager plugins,
    and the result of their initialization function (context).
    """

    def __init__(self, am_conf):
        self.context = dict()
        self.attribute_fetcher = dict()

        for plugin_name in worker_config.get('ACTION_PLUGINS', []):
            module_name = 'eduid_action.{}.am'.format(plugin_name)
            try:
                plugin_module = import_module(module_name)
            except ImportError as exc:
                logger.warn('Configured plugin {} missing from sys.path (could not import {}): {}'.format(
                    plugin_name, module_name, exc))
                logger.debug('Extra debug: path: {}'.format(sys.path))
                continue
            logger.info('Registering action plugin: {} (module {})'.format(plugin_name, module_name))

            plugin_init = getattr(plugin_module, 'plugin_init')
            self.context[plugin_name] = plugin_init(am_conf)

            attr_fetcher = getattr(plugin_module, 'attribute_fetcher')
            self.attribute_fetcher[plugin_name] = attr_fetcher

        for entry_point in iter_entry_points('eduid_am.plugin_init'):
            if entry_point.name in self.context:
                logger.warn('Duplicate plugin_init entry point: {!r}'.format(entry_point.name))
            else:
                logger.debug('Calling plugin_init entry point for {!r}'.format(entry_point.name))
                plugin_init = entry_point.load()
                self.context[entry_point.name] = plugin_init(am_conf)

        for entry_point in iter_entry_points('eduid_am.attribute_fetcher'):
            if entry_point.name in self.attribute_fetcher:
                logger.warn('Duplicate attribute_fetcher entry point: {!r}'.format(entry_point.name))
            else:
                logger.debug('Registering attribute_fetcher entry point for {!r}'.format(entry_point.name))
                self.attribute_fetcher[entry_point.name] = entry_point.load()


class AttributeManager(Task):
    """Singleton that stores reusable objects like the entry points registry
    or the MongoDB database."""

    abstract = True  # This means Celery won't register this as another task

    def __init__(self):
        self.default_db_uri = worker_config.get('MONGO_URI')
        if self.default_db_uri is not None:
            # self.userdb is the UserDB to which AM will write the updated users. This setting will
            # be None when this class is instantiated on the 'client' side (e.g. in a microservice)
            self.userdb = self.init_db()
        self.registry = PluginsRegistry(worker_config)

    def init_db(self):
        return UserDB(self.default_db_uri, 'eduid_am', 'attributes')

    def reload_db(self):
        self.userdb = self.init_db()

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        # Try to reload the db on connection failures (mongodb has probably switched master)
        if isinstance(exc, ConnectionError):
            logger.error('Task failed with db exception ConnectionError. Reloading db.')
            self.reload_db()


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
        attribute_fetcher = self.registry.attribute_fetcher[app_name]
    except KeyError:
        logger.error('Plugin for {!s} is not installed'.format(app_name))
        return

    logger.debug("Attribute fetcher for {!s}: {!r}".format(app_name, attribute_fetcher))

    try:
        _id = bson.ObjectId(user_id)
    except bson.errors.InvalidId:
        logger.error('Invalid user_id {!s} from app {!s}'.format(user_id, app_name))
        raise ValueError('Bad user_id')

    try:
        _context = self.registry.context[app_name]
    except KeyError:
        logger.error('Plugin for {!s} is not initialized'.format(app_name))
        return

    logger.debug("Context for {!s}: {!r}".format(app_name, _context))

    try:
        attributes = attribute_fetcher(_context, _id)
    except UserDoesNotExist as error:
        logger.error('The user {!s} does not exist in the database for plugin {!s}: {!s}'.format(
            _id, app_name, error))
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
