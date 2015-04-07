#
# Copyright (c) 2015 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

from bson import ObjectId

from eduid_userdb.user import User
from eduid_userdb.db import MongoDB
import eduid_userdb.exceptions
from eduid_userdb.exceptions import UserDoesNotExist, MultipleUsersReturned

import logging
logger = logging.getLogger(__name__)


class UserDB(object):
    """
    Interface class to the central eduID UserDB.
    """

    UserClass = User

    def __init__(self, db_uri, collection='userdb'):

        self._db = MongoDB(db_uri)
        self._coll = self._db.get_collection(collection)
        logger.debug("{!s} UserDB connected to {!s} {!r} / {!s})".format(
            self, db_uri, collection, self._coll))
        if db_uri.endswith('am'):
            raise ValueError('foo')
        # XXX Backwards compatibility.
        # Was: provide access to our backends exceptions to users of this class
        self.exceptions = eduid_userdb.exceptions

    def get_user_by_id(self, user_id):
        """
        Locate a user in the userdb given the user's _id.

        :param user_id: User identifier
        :type user_id: bson.ObjectId | str | unicode
        :return: UserClass instance
        :rtype: UserClass

        :raise self.UserDoesNotExist: No user match the search criteria
        :raise self.MultipleUsersReturned: More than one user matches the search criteria
        """
        if not isinstance(user_id, ObjectId):
            user_id = ObjectId(user_id)
        return self._get_user_by_attr('_id', user_id)

    def get_user_by_mail(self, email, raise_on_missing=False, include_unconfirmed=False):
        """
        Return the user object in the central eduID UserDB having
        an email address matching `email'. Unless include_unconfirmed=True, the
        email address has to be confirmed/verified.

        :param email: The email address to look for
        :param raise_on_missing: If True, raise exception if no matching user object can be found.
        :param include_unconfirmed: Require email address to be confirmed/verified.

        :type email: str | unicode
        :type raise_on_missing: bool
        :type include_unconfirmed: bool

        :return: User instance
        :rtype: UserClass
        """
        email = email.lower()
        elemmatch = {'email': email, 'verified': True}
        if include_unconfirmed:
            elemmatch = {'email': email}
        # XXX this only looks in the legacy collection, in the legacy format
        docs = self._coll.find(
            {'$or': [
                {'mail': email},
                {'mailAliases': {'$elemMatch': elemmatch}}
            ]})
        users = []
        if docs.count() > 0:
            users = list(docs)
        if not users:
            logging.debug("{!s} No user found with email {!r} in {!r}".format(self, email, self._coll))
            if raise_on_missing:
                raise UserDoesNotExist("No user matching email {!r}".format(email))
            return None
        elif len(users) > 1:
            raise MultipleUsersReturned("Multiple matching users for email {!r}".format(email))
        return self.UserClass(data=users[0])

    def get_user_by_eppn(self, eppn):
        """
        Look for a user using the eduPersonPrincipalName.

        :param eppn: eduPersonPrincipalName to look for
        :type eppn: str | unicode

        :return: UserClass instance
        :rtype: UserClass
        """
        return self._get_user_by_attr('eduPersonPrincipalName', eppn)

    def _get_user_by_attr(self, attr, value):
        """
        Locate a user in the userdb using any attribute and value.

        This is a private function since callers can't depend on the name of things in the db.

        :param attr: The attribute to match on
        :param value: The value to match on
        :return: UserClass instance
        :rtype: UserClass
        :raise self.UserDoesNotExist: No user match the search criteria
        :raise self.MultipleUsersReturned: More than one user matches the search criteria
        """
        logger.debug("{!s} Looking in {!r} for user with {!r} = {!r}".format(
            self, self._coll, attr, value))
        try:
            doc = self._get_document_by_attr(attr, value, raise_on_missing=True)
            logger.debug("{!s} Found user {!r}".format(self, doc))
            return self.UserClass(data=doc)
        except self.exceptions.UserDoesNotExist:
            logger.debug("UserDoesNotExist, {!r} = {!r}".format(attr, value))
            raise
        except self.exceptions.MultipleUsersReturned:
            logger.error("MultipleUsersReturned, {!r} = {!r}".format(attr, value))
            raise

    def _get_document_by_attr(self, attr, value, raise_on_missing=False):
        """
        Return the user object in the attribute manager MongoDB matching field=value

        :param attr: The name of a field
        :param value: The field value
        :param raise_on_missing: If True, raise exception if no matching user object can be found.
        :return: A user dict
        """
        #logging.debug("get_user_by_field %s=%s" % (field, value))

        docs = self._coll.find({attr: value})
        if docs.count() == 0:
            if raise_on_missing:
                raise UserDoesNotExist("No user matching %s='%s'" % (attr, value))
            return None
        elif docs.count() > 1:
            raise MultipleUsersReturned("Multiple matching users for %s='%s'" % (attr, value))
        return docs[0]

    def save(self, user, check_sync=True, old_format=False):
        """

        :param user: UserClass object
        :param check_sync: Ensure the user hasn't been updated in the database since it was loaded
        :param old_format: Save the user in legacy format in the database

        :type user: UserClass
        :type check_sync: bool
        :type old_format: bool
        :return:
        """
        assert isinstance(user.user_id, ObjectId)
        # XXX add modified_by info. modified_ts alone is not unique when propagated to eduid_am.

        modified = user.modified_ts
        user.modified_ts = True  # update to current time
        if modified is None:
            # profile has never been modified through the dashboard.
            # possibly just created in signup.
            result = self._coll.insert(user.to_dict(old_userdb_format=old_format))
            logging.debug("{!s} Inserted new user {!r} into {!r}: {!r}".format(self, user, self._coll, result))
        else:
            test_doc = {'_id': user.user_id}
            if check_sync:
                test_doc['modified_ts'] = modified
            result = self._coll.update(test_doc, user.to_dict(old_userdb_format=old_format))
            logging.debug("{!s} Updated user {!r} in {!r}: {!r}".format(self, user, self._coll, result))
            if check_sync and result['n'] == 0:
                raise eduid_userdb.exceptions.UserOutOfSync('Stale user object can\'t be saved')
        return result

    def remove_user_by_id(self, user_id):
        """
        Remove a user in the userdb given the user's _id.

        NOTE: Full removal of a user should never be done in the central userdb. Kantara
        requires guarantees to not re-use user identifiers (eppn and _id in eduid) and
        we implenent that by never removing the complete document from the central userdb.

        Some other applications might have legitimate reasons to remove users from their
        private userdb collections though (like eduid-signup, at the end of the signup
        process).

        This method should ideally then only be available on eduid_signup.userdb.SignupUserDB
        objects, but then eduid-am would have to depend on eduid_signup... Maybe the cleanup
        could be done by the Signup application itself though.

        :param user_id: User id
        :type user_id: bson.ObjectId
        """
        logger.debug("{!s} Removing user with id {!r} from {!s}".format(self, user_id, self._coll))
        return self._coll.remove(spec_or_id=user_id)

    def _drop_whole_collection(self):
        """
        Drop the whole collection. Should ONLY be used in testing, obviously.
        :return:
        """
        logging.warning("{!s} Dropping collection {!s}".format(self, self._coll))
        return self._coll.drop()

    def update_user(self, obj_id, attributes):
        """
        Update user document in mongodb.

        `attributes' can be either a dict with plain key-values, or a dict with
        one or more find_and_modify modifier instructions ({'$set': ...}).

        This update method should only be used in the eduid Attribute Manager when
        merging updates from applications into the central eduid UserDB.

        :param obj_id: ObjectId
        :param attributes: dict
        :return: None
        """
        logger.debug("{!s} updating user {!r} in {!s} with attributes:\n{!s}".format(
            self, obj_id, self._coll, attributes))

        doc = {'_id': obj_id}

        # check if any of doc attributes contains a modifier instruction.
        # like any key starting with $
        #
        if all([attr.startswith('$') for attr in attributes]):
            self._coll.find_and_modify(doc, attributes)
        else:
            if self._coll.find(doc).count() == 0:
                # The object is a new object
                doc.update(attributes)
                self._coll.save(doc)
            else:
                # Dont overwrite the entire object, only the defined
                # attributes
                self._coll.find_and_modify(
                    doc,
                    {
                        '$set': attributes,
                    }
                )

    def db_count(self):
        """
        Return number of entries in the database.

        Used in eduid-signup test cases.
        :return: User count
        :rtype: int
        """
        return self._coll.find({}).count()
