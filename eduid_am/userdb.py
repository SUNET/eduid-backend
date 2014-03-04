from bson import ObjectId

from eduid_am.celery import celery, get_attribute_manager
from eduid_am.user import User
import eduid_am.exceptions
import eduid_am.tasks  # flake8: noqa

import logging
logger = logging.getLogger(__name__)


class UserDB(object):

    def __init__(self, settings):

        am_settings = {'MONGO_URI': settings['mongo_uri_am']}

        mongo_replicaset = settings.get('mongo_replicaset', None)

        if mongo_replicaset is not None:
            am_settings['replicaSet'] = mongo_replicaset

        celery.conf.update(am_settings)
        self._db = get_attribute_manager(celery)
        self.settings = settings
        self.user_main_attribute = settings.get('saml2.user_main_attribute',
                                                'mail')
        # provide access to our backends exceptions to users of this class
        self.exceptions = eduid_am.exceptions

    def get_user(self, userid):
        """
        Locate a user in the userdb using the main attribute (typically 'mail').
        The name of the main attribute can be influenced in __init__().

        :param userid: string
        :return: eduid_am.user.User
        :raise self.UserDoesNotExist: No user match the search criteria
        :raise self.MultipleUsersReturned: More than one user matches the search criteria
        """
        return self.get_user_by_attr(self.user_main_attribute, userid)

    def get_user_by_email(self, email):
        doc = self._db.get_user_by_mail(email, raise_on_missing=True)
        return User(doc)

    def get_user_by_username(self, username):
        users = self.get_users({'eduPersonPrincipalName': username})
        if users.count() == 0:
            raise self.exceptions.UserDoesNotExist()
        if users.count() > 1:
            raise self.exceptions.MultipleUsersReturned()
        return User(users[0])

    def get_user_by_nin(self, nin):
        users = self.get_users({
            'norEduPersonNIN.norEduPersonNIN': nin,
            'norEduPersonNIN.verified': True,
            'norEduPersonNIN.active': True,
        })
        if users.count() == 0:
            raise self.exceptions.UserDoesNotExist()
        if users.count() > 1:
            raise self.exceptions.MultipleUsersReturned()
        return User(users[0])

    def get_user_by_oid(self, oid):
        """
        Locate a user in the userdb given the user's _id.

        :param oid: ObjectId() or string
        :return: eduid_am.user.User
        :raise self.UserDoesNotExist: No user match the search criteria
        :raise self.MultipleUsersReturned: More than one user matches the search criteria
        """
        if not isinstance(oid, ObjectId):
            oid = ObjectId(oid)
        return self.get_user_by_attr('_id', oid)

    def get_user_by_attr(self, attr, value):
        """
        Locate a user in the userdb using any attribute and value.

        :param attr: The attribute to match on
        :param value: The value to match on
        :return: eduid_am.user.User
        :raise self.UserDoesNotExist: No user match the search criteria
        :raise self.MultipleUsersReturned: More than one user matches the search criteria
        """
        logger.debug("Looking in {!r} for user with {!r} = {!r}".format(
            self._db, attr, value))
        try:
            doc = self._db.get_user_by_field(attr, value, raise_on_missing=True)
            logger.debug("Found user {!r}".format(doc))
            return User(doc)
        except self.exceptions.UserDoesNotExist:
            logger.debug("UserDoesNotExist, {!r} = {!r}".format(attr, value))
            raise self.exceptions.UserDoesNotExist()
        except self.exceptions.MultipleUsersReturned:
            logger.error("MultipleUsersReturned, {!r} = {!r}".format(attr, value))
            raise self.exceptions.MultipleUsersReturned()

    def exists_by_field(self, field, value):
        return self._db.exists_by_field(field, value)

    def exists_by_filter(self, filter):
        return self._db.exists_by_filter(filter)

    def get_users(self, filter, proyection=None):
        return self._db.get_users(filter, proyection)

    def get_identity_proofing(self, user):
        return self._db.get_identity_proofing(user['_id'])


def get_userdb(request):
    return request.registry.settings['userdb']
