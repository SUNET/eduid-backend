"""
This is the eduid attribute manager. The main entry point is the celery task which
is wired to receive notifications from a message bus. The notifications contain a
name and serialized ObjectId which is dispatched to plugins that provide 'update'
in the group name.

The resulting dict is merged (or inserted) into the attribute manager's mongodb.
"""

__author__ = 'leifj'

import logging
from celery import current_app
from pymongo import MongoClient
from urlparse import urlparse
from pkg_resources import working_set, Environment
from bson.objectid import ObjectId
from celery import task


class AttributeException(Exception):
    pass


class NoSuchUserException(AttributeException):
    pass


class MultipleMatchingUserException(AttributeException):
    pass


_instance = None


def set_instance(self):
    global _instance
    _instance = self


def get_instance():
    global _instance
    if _instance is None:
        raise ValueError("Uninitialized")
    return _instance


@task(name="eduid.am.update")
def update(application, id):
    """

    :param application: The name of the application requesting the update
    :param id: The id of the object updated

Identifies all plugins associated with 'application' and looks up the 'update' entry point using
iter_entry_points. For each application, lookup the object in the attribute manager MongoDB and
either create it if missing or update it with the data returned by the plugin entry point.

    """
    self = get_instance()
    logging.debug("update %s[%s]" % (application, id))
    try:
        if not application in self._apps:
            for entry_point in working_set.iter_entry_points(application, 'update'):
                self.register(self, application, entry_point.load())

        if application in self._apps:
            oid = ObjectId(id)
            doc = self.db.attributes.find_one({'_id': oid}, {'_id': True})
            for fn in self._apps[application]:
                attrs = fn(id)
                attrs['_id'] = id
                if doc is None:
                    doc = self.db.attributes.insert(attrs)
                else:
                    self.db.attributes.update(attrs)
        else:
            logging.warning("No plugin registered for %s" % application)
    except Exception, ex:
        logging.error(ex)


class AttributeManager(object):
    def __init__(self, settings=dict()):
        self.settings = settings
        self._db = settings.get('_db', None)
        self._apps = dict()
        current_app.config_from_object(self.settings)
        self.celery = current_app

        if 'plugins' in settings:
            distributions, errors = working_set.find_plugins(Environment(settings['plugins']))
            map(working_set.add, distributions)  # add plugins+libs to sys.path
            if errors:
                logging.error("Couldn't load plugins: " % errors)  # display errors

        set_instance(self)

    @property
    def db(self):
        """
        Return a mongodb instance for the attribute manager based on the settings object.

        :return: A connected mongodb database.
        :raise: ValueError unless connection details can be infered from mongo_uri key in settings
        """
        if self._db is None:
            url = self.settings.get('mongo_uri', None)
            if url is None:
                raise ValueError("No mongo_uri in settings object")
            db_url = urlparse(url)
            logging.debug("Creating connection to %s:%s" % (db_url.hostname, db_url.port))
            c = MongoClient('%s:%s' % (db_url.hostname, db_url.port))
            db = getattr(c, db_url.path)
            if db_url.username and db_url.password:
                logging.debug("Authenticating connection")
                db.authenticate(db_url.username, db_url.password)
            self._db = db
        return self._db

    def register(self, name, cb):
        """

        :param name: the name under which to register the callback
        :param cb: a callable object to register

Insert a single callback in the registry for 'name'. All callables must take two arguments.
        """
        if not name in self._apps:
            self._apps[name] = []
        self._apps[name].append(cb)

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
        logging.debug("get_user_by_field %s=%s" % (field, value))
        docs = self.db.attributes.find({field: value})
        if 0 == docs.count():
            if raise_on_missing:
                raise NoSuchUserException("No user matching %s='%s'" % (field, value))
            else:
                return None
        elif 1 > docs.count():
            raise MultipleMatchingUserException("Multiple matching users for %s='%s'" % (field, value))
        else:
            return docs[0]