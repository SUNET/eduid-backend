from __future__ import absolute_import

from celery import Task
from celery.utils.log import get_task_logger

from pkg_resources import iter_entry_points

import bson

from eduid_am.celery import celery
from eduid_am.db import MongoDB, DEFAULT_MONGODB_URI
from eduid_am.exceptions import UserDoesNotExist

logger = get_task_logger(__name__)


class PluginsRegistry(dict):

    def __init__(self):
        for entry_point in iter_entry_points('eduid_am.attribute_fetcher'):
            if entry_point.name in self:
                logger.warn("Duplicate entry point: %s" % entry_point.name)
            else:
                logger.debug("Registering entry point: %s" % entry_point.name)
                self[entry_point.name] = entry_point.load()


class AttributeManager(Task):
    """Singleton that stores reusable objects like the entry points registry
    or the MongoDB database."""

    abstract = True  # This means Celery won't register this as another task
    registry = PluginsRegistry()
    _db = None

    @property
    def db(self):
        if self._db is None:
            conn = MongoDB(self.app.conf.get('MONGO_URI', DEFAULT_MONGODB_URI))
            self._db = conn.get_database()
        return self._db

    def update_user(self, user_id, attributes):
        doc = {'_id': user_id}
        doc.update(attributes)
        self.db.users.save(doc)


@celery.task(ignore_results=True, base=AttributeManager)
def update_attributes(app_name, user_id):
    self = update_attributes
    logger.debug("update %s[%s]" % (app_name, user_id))
    try:
        attribute_fetcher = self.registry[app_name]
    except KeyError:
        logger.error('Plugin for %s is not installed' % app_name)
        return

    try:
        _id = bson.ObjectId(user_id)
    except bson.errors.InvalidId:
        logger.error('Invalid user_id %s from app %s' % (user_id, app_name))
        return

    try:
        attributes = attribute_fetcher(self.db, _id)
    except UserDoesNotExist:
        logger.error('The user %s does not exist in the collection for app %s'
                     % (user_id, app_name))
        return

    logger.debug('Attributes fetched from app %s for user %s: %s'
                 % (app_name, user_id, attributes))
    self.update_user(_id, attributes)
