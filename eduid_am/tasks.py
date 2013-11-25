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
        db_name = (self.app.conf.get('MONGO_DBNAME') or None)
        if db_name:
            return self.conn.get_database(db_name)
        else:
            return self.conn.get_database()

    def update_user(self, user_id, attributes):
        doc = {'_id': user_id}

        # check if any of doc attributes contains a modifer instruction.
        # like any key starting with $
        #
        if all([attr.startswith('$') for attr in attributes]):
            self.db.attributes.find_and_modify(doc, attributes)
        else:
            if self.db.attributes.find(doc).count() == 0:
                # The object is a new object
                doc.update(attributes)
                self.db.attributes.save(doc)
            else:
                # Dont overwrite the entire object, only the defined
                # attributes
                self.db.attributes.find_and_modify(
                    doc,
                    {
                        '$set': attributes,
                    }
                )

    def get_user_by_id(self, id, raise_on_missing=False):
        """
        Return the user object in the attribute manager MongoDB with _id=id

        :param id: An Object ID
        :param raise_on_missing: If True, raise exception if no matching user object can be found.
        :return: A user dict
        """
        return self.get_user_by_field('_id', id, raise_on_missing)

    def get_user_by_field(self, field, value, raise_on_missing=False):
        """
        Return the user object in the attribute manager MongoDB matching field=value

        :param field: The name of a field
        :param value: The field value
        :param raise_on_missing: If True, raise exception if no matching user object can be found.
        :return: A user dict
        """
        #logging.debug("get_user_by_field %s=%s" % (field, value))

        docs = self.db.attributes.find({field: value})
        if docs.count() == 0:
            if raise_on_missing:
                raise UserDoesNotExist("No user matching %s='%s'" % (field,
                                                                     value))
            else:
                return None
        elif docs.count() > 1:
            raise MultipleUsersReturned("Multiple matching users for %s='%s'" %
                                        (field, value))
        else:
            return docs[0]

    def get_users(self, spec, fields=None):
        """
        Return a list with users object in the attribute manager MongoDB matching the filter

        :param spec: a standard mongodb read operation filter
        :param fields: If not None, pass as proyection to mongo searcher
        :return a list with users
        """
        #logging.debug("get_users %s=%s" % (filter))

        if fields is None:
            return self.db.attributes.find(spec)
        else:
            return self.db.attributes.find(spec, fields)

    def exists_by_filter(self, spec):
        """
        Return true if at least one doc matchs with the value

        :param spec: The filter used in the query
        """

        docs = self.db.attributes.find(spec)
        return docs.count() >= 1

    def exists_by_field(self, field, value):
        """
        Return true if at least one doc matchs with the value

        :param field: The name of a field
        :param value: The field value
        """

        return self.exists_by_filter({field: value})

    def get_identity_proofing(self, obj_id):
        """
        Return the proofing urn value

        :param obj_id: The user object id
        """

        # TODO
        # This method need to be implemented
        default_urn = 'http://www.swamid.se/assurance/al1'
        user = self.db.attributes.find_one({'_id': obj_id})
        if user is None:
            return default_urn
        else:
            return user.get('eduPersonIdentityProofing',
                            'http://www.swamid.se/assurance/al1')


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
    try:
        return _update_attributes_safe(app_name, obj_id)
    except Exception as exc:
        logger.error("Got exception processing {!r}[{!r}]".format(app_name, obj_id), exc_info = True)
        raise


def _update_attributes_safe(app_name, user_id):
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
    logger.debug("Got database {!r}/{!s} for plugin".format(plugin_db,
                                                            plugin_db))
    try:
        attributes = attribute_fetcher(plugin_db, _id)
    except UserDoesNotExist as error:
        logger.error('The user %s does not exist in the database for plugin %s: %s' % (
            _id, app_name, error))
        return

    logger.debug('Attributes fetched from app %s for user %s: %s'
                 % (app_name, user_id, attributes))
    self.update_user(_id, attributes)
