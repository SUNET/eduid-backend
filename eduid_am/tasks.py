from __future__ import absolute_import

from celery import Task
from celery.utils.log import get_task_logger

from pkg_resources import iter_entry_points

import bson

from eduid_am.celery import celery
from eduid_userdb import UserDB
from eduid_userdb.db import DEFAULT_MONGODB_URI
from eduid_userdb.exceptions import UserDoesNotExist

logger = get_task_logger(__name__)

USERDBS = {}


class PluginsRegistry(object):

    def __init__(self, db_uri, am_conf):
        self.context = dict()
        self.attribute_fetcher = dict()

        for entry_point in iter_entry_points('eduid_am.plugin_init'):
            if entry_point.name in self.context:
                logger.warn("Duplicate plugin_init entry point: {}".format(entry_point.name))
            else:
                logger.debug("Calling plugin_init entry point: {}".format(entry_point.name))
                plugin_init = entry_point.load()
                self.context[entry_point.name] = plugin_init(db_uri, am_conf)

        for entry_point in iter_entry_points('eduid_am.attribute_fetcher'):
            if entry_point.name in self.attribute_fetcher:
                logger.warn("Duplicate entry point: %s" % entry_point.name)
            else:
                logger.debug("Registering entry point: %s" % entry_point.name)
                self.attribute_fetcher[entry_point.name] = entry_point.load()


class AttributeManager(Task):
    """Singleton that stores reusable objects like the entry points registry
    or the MongoDB database."""

    abstract = True  # This means Celery won't register this as another task

    def __init__(self, db_uri=None):
        """
        @param db_uri: Database URI to save updated users in (old: eduid_am.attributes, new: eduid_userdb.userdb)
        """
        if db_uri is None:
            db_uri = self.app.conf.get('MONGO_URI', DEFAULT_MONGODB_URI)
        # When testing, the default_db_uri can be overridden with a path to a temporary MongoDB instance.
        self.default_db_uri = db_uri

        _collection = 'userdb'
        # Hack to get right collection name while the configuration points to the old database
        if self.default_db_uri.endswith('/eduid_am'):
            _collection = 'attributes'
        # self.userdb is the UserDB to which AM will write the updated users
        self.userdb = UserDB(self.default_db_uri, collection=_collection)

        self.registry = PluginsRegistry(db_uri, self.app.conf)


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
    logger.debug("Update attributes called for {!r} by {!r}".format(obj_id, app_name))
    try:
        return _update_attributes_safe(app_name, obj_id)
    except Exception:
        logger.error("Got exception processing {!r}[{!r}]".format(app_name, obj_id), exc_info = True)
        raise


def _update_attributes_safe(app_name, user_id):
    self = update_attributes
    logger.debug("update %s[%s]" % (app_name, user_id))

    try:
        attribute_fetcher = self.registry.attribute_fetcher[app_name]
    except KeyError:
        logger.error('Plugin for %s is not installed'.format(app_name))
        return

    try:
        _id = bson.ObjectId(user_id)
    except bson.errors.InvalidId:
        logger.error('Invalid user_id %s from app %s' % (user_id, app_name))
        raise ValueError('Bad user_id')

    try:
        _context = self.registry.context[app_name]
    except KeyError:
        logger.error('Plugin for %s is not initialized'.format(app_name))
        return

    try:
        attributes = attribute_fetcher(_context, _id)
    except UserDoesNotExist as error:
        logger.error('The user %s does not exist in the database for plugin %s: %s' % (
            _id, app_name, error))
        return

    logger.debug('Attributes fetched from app %s for user %s: %s'
                 % (app_name, user_id, attributes))
    self.userdb.update_user(_id, attributes)
