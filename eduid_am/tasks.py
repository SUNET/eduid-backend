from __future__ import absolute_import

from celery import Task
from celery.utils.log import get_task_logger

from pkg_resources import iter_entry_points

import bson

from eduid_am.celery import celery
from eduid_am.db import MongoDB, DEFAULT_MONGODB_URI
from eduid_am.exceptions import UserDoesNotExist, MultipleUsersReturned

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
    _conn = None

    @property
    def conn(self):
        if self._conn is None:
            self._conn = MongoDB(self.app.conf.get('MONGO_URI', DEFAULT_MONGODB_URI))
        return self._conn

    @property
    def db(self):
        return self.conn.get_database('am')

    def update_user(self, user_id, attributes):
        doc = {'_id': user_id}
        doc.update(attributes)
        self.db.attributes.save(doc)

    def get_user_by_id(self, id, raise_on_missing=False):
        """

        :param id: An Object ID
        :param raise_on_missing: If True, raise exception if no matching user object can be found.
        :return: A user dict

Return the user object in the attribute manager MongoDB with _id=id
        """
        return self.get_user_by_field('_id', id, raise_on_missing)

    def get_user_by_field(self, field, value, raise_on_missing=False):
        """

        :param field: The name of a field
        :param value: The field value
        :param raise_on_missing: If True, raise exception if no matching user object can be found.
        :return: A user dict

Return the user object in the attribute manager MongoDB matching field=value
        """
        #logging.debug("get_user_by_field %s=%s" % (field, value))

        docs = self.db.attributes.find({field: value})
        if 0 == docs.count():
            if raise_on_missing:
                raise UserDoesNotExist("No user matching %s='%s'" % (field, value))
            else:
                return None
        elif 1 > docs.count():
            raise MultipleUsersReturned("Multiple matching users for %s='%s'" % (field, value))
        else:
            return docs[0]


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

    plugin_db = self.conn.get_database(app_name)
    try:
        attributes = attribute_fetcher(plugin_db, _id)
    except UserDoesNotExist as error:
        logger.error('The user %s does not exist in the database for app %s' % error)
        return

    logger.debug('Attributes fetched from app %s for user %s: %s'
                 % (app_name, user_id, attributes))
    self.update_user(_id, attributes)


