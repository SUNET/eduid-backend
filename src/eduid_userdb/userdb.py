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
import logging
from datetime import datetime
from typing import Mapping, Type

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import ReturnDocument

import eduid_userdb.exceptions
from eduid_userdb.db import BaseDB
from eduid_userdb.exceptions import DocumentDoesNotExist, EduIDUserDBError, MultipleUsersReturned, UserDoesNotExist
from eduid_userdb.user import User

logger = logging.getLogger(__name__)


class UserDB(BaseDB):
    """
    Interface class to the central eduID UserDB.

    :param db_uri: mongodb:// URI to connect to
    :param db_name: mongodb database name
    :param collection: mongodb collection name

    :type db_uri: str or unicode
    :type db_name: str or unicode
    :type collection: str or unicode
    """

    UserClass: Type[User] = User

    def __init__(self, db_uri, db_name, collection='userdb', user_class=None):

        if db_name == 'eduid_am' and collection == 'userdb':
            # Hack to get right collection name while the configuration points to the old database
            collection = 'attributes'
        self.collection = collection

        super(UserDB, self).__init__(db_uri, db_name, collection)

        if user_class is not None:
            self.UserClass = user_class

        logger.debug("{!s} connected to database".format(self))
        # XXX Backwards compatibility.
        # Was: provide access to our backends exceptions to users of this class
        self.exceptions = eduid_userdb.exceptions

    def __repr__(self):
        return '<eduID {!s}: {!s} {!r} (returning {!s})>'.format(
            self.__class__.__name__, self._db.sanitized_uri, self._coll_name, self.UserClass.__name__,
        )

    def get_user_by_id(self, user_id, raise_on_missing=True):
        """
        Locate a user in the userdb given the user's _id.

        :param user_id: User identifier
        :param raise_on_missing: If True, raise exception if no matching user object can be found.

        :type user_id: bson.ObjectId | str | unicode
        :type raise_on_missing: bool

        :return: UserClass instance | None
        :rtype: UserClass | None

        :raise self.UserDoesNotExist: No user match the search criteria
        :raise self.MultipleUsersReturned: More than one user matches the search criteria
        """
        if not isinstance(user_id, ObjectId):
            try:
                user_id = ObjectId(user_id)
            except InvalidId:
                return None
        return self._get_user_by_attr('_id', user_id, raise_on_missing)

    def _get_user_by_filter(self, filter, raise_on_missing=True, return_list=False):
        """
        return the user matching the provided filter.

        :param filter: The filter to match the user
        :param raise_on_missing: If True, raise exception if no matching user object can be found.
        :param return_list: If True, always return a list of user objects regardless of how many there is.

        :type filter: dict
        :type raise_on_missing: bool
        :type return_list: bool

        :return: User instance
        :rtype: UserClass
        """
        try:
            users = list(self._get_documents_by_filter(filter, raise_on_missing=raise_on_missing))
        except DocumentDoesNotExist:
            logger.debug("{!s} No user found with filter {!r} in {!r}".format(self, filter, self._coll_name))
            raise UserDoesNotExist("No user matching filter {!r}".format(filter))

        if return_list:
            return [self.UserClass.from_dict(data=user) for user in users]

        if len(users) == 0:
            return None

        if len(users) > 1:
            raise MultipleUsersReturned("Multiple matching users for filter {!r}".format(filter))

        return self.UserClass.from_dict(data=users[0])

    def get_user_by_mail(self, email, raise_on_missing=True, return_list=False, include_unconfirmed=False):
        """
        Return the user object in the central eduID UserDB having
        an email address matching `email'. Unless include_unconfirmed=True, the
        email address has to be confirmed/verified.

        :param email: The email address to look for
        :param raise_on_missing: If True, raise exception if no matching user object can be found.
        :param return_list: If True, always return a list of user objects regardless of how many there is.
        :param include_unconfirmed: Require email address to be confirmed/verified.

        :type email: str | unicode
        :type raise_on_missing: bool
        :type return_list: bool
        :type include_unconfirmed: bool

        :return: User instance
        :rtype: UserClass
        """
        email = email.lower()
        elemmatch = {'email': email, 'verified': True}
        if include_unconfirmed:
            elemmatch = {'email': email}
        filter = {'$or': [{'mail': email}, {'mailAliases': {'$elemMatch': elemmatch}}]}
        return self._get_user_by_filter(filter, raise_on_missing=raise_on_missing, return_list=return_list)

    def get_user_by_nin(self, nin, raise_on_missing=True, return_list=False, include_unconfirmed=False):
        """
        Return the user object in the central eduID UserDB having
        a NIN matching `nin'. Unless include_unconfirmed=True, the
        NIN has to be confirmed/verified.

        :param nin: The nin to look for
        :param raise_on_missing: If True, raise exception if no matching user object can be found.
        :param return_list: If True, always return a list of user objects regardless of how many there is.
        :param include_unconfirmed: Require nin to be confirmed/verified.

        :type nin: str | unicode
        :type raise_on_missing: bool
        :type return_list: bool
        :type include_unconfirmed: bool

        :return: User instance
        :rtype: UserClass
        """
        old_filter = {'norEduPersonNIN': nin}
        newmatch = {'number': nin, 'verified': True}
        if include_unconfirmed:
            newmatch = {'number': nin}
        new_filter = {'nins': {'$elemMatch': newmatch}}
        filter = {'$or': [old_filter, new_filter]}
        return self._get_user_by_filter(filter, raise_on_missing=raise_on_missing, return_list=return_list)

    def get_user_by_phone(self, phone, raise_on_missing=True, return_list=False, include_unconfirmed=False):
        """
        Return the user object in the central eduID UserDB having
        a phone number matching `phone'. Unless include_unconfirmed=True, the
        phone number has to be confirmed/verified.

        :param phone: The phone to look for
        :param raise_on_missing: If True, raise exception if no matching user object can be found.
        :param return_list: If True, always return a list of user objects regardless of how many there is.
        :param include_unconfirmed: Require phone to be confirmed/verified.

        :type phone: str | unicode
        :type raise_on_missing: bool
        :type return_list: bool
        :type include_unconfirmed: bool

        :return: User instance
        :rtype: UserClass
        """
        oldmatch = {'mobile': phone, 'verified': True}
        if include_unconfirmed:
            oldmatch = {'mobile': phone}
        old_filter = {'mobile': {'$elemMatch': oldmatch}}
        newmatch = {'number': phone, 'verified': True}
        if include_unconfirmed:
            newmatch = {'number': phone}
        new_filter = {'phone': {'$elemMatch': newmatch}}
        filter = {'$or': [old_filter, new_filter]}
        return self._get_user_by_filter(filter, raise_on_missing=raise_on_missing, return_list=return_list)

    def get_user_by_eppn(self, eppn, raise_on_missing=True):
        """
        Look for a user using the eduPersonPrincipalName.

        :param eppn: eduPersonPrincipalName to look for
        :param raise_on_missing: If True, raise exception if no matching user object can be found.

        :type eppn: str | unicode
        :type raise_on_missing: bool

        :return: UserClass instance
        :rtype: UserClass
        """
        return self._get_user_by_attr('eduPersonPrincipalName', eppn, raise_on_missing)

    def _get_user_by_attr(self, attr, value, raise_on_missing=True):
        """
        Locate a user in the userdb using any attribute and value.

        This is a private function since callers can't depend on the name of things in the db.

        :param attr: The attribute to match on
        :param value: The value to match on
        :param raise_on_missing: If True, raise exception if no matching user object can be found.

        :return: UserClass instance | None
        :rtype: UserClass | None
        :raise self.UserDoesNotExist: No user match the search criteria
        :raise self.MultipleUsersReturned: More than one user matches the search criteria
        """
        user = None
        logger.debug("{!s} Looking in {!r} for user with {!r} = {!r}".format(self, self._coll_name, attr, value))
        try:
            doc = self._get_document_by_attr(attr, value, raise_on_missing)
            if doc is not None:
                logger.debug("{!s} Found user with id {!s}".format(self, doc['_id']))
                user = self.UserClass.from_dict(data=doc)
                logger.debug("{!s} Returning user {!s}".format(self, user))
            return user
        except self.exceptions.DocumentDoesNotExist as e:
            logger.debug("UserDoesNotExist, {!r} = {!r}".format(attr, value))
            raise UserDoesNotExist(e.reason)
        except self.exceptions.MultipleDocumentsReturned as e:
            logger.error("MultipleUsersReturned, {!r} = {!r}".format(attr, value))
            raise MultipleUsersReturned(e.reason)

    def save(self, user: User, check_sync: bool = True, old_format: bool = False) -> bool:
        """
        :param user: UserClass object
        :param check_sync: Ensure the user hasn't been updated in the database since it was loaded
        :param old_format: Save the user in legacy format in the database
        """
        if not isinstance(user, self.UserClass):
            raise EduIDUserDBError('user is not of type {}'.format(self.UserClass))

        if not isinstance(user.user_id, ObjectId):
            raise AssertionError('user.user_id is not of type {}'.format(ObjectId))

        # XXX add modified_by info. modified_ts alone is not unique when propagated to eduid_am.

        modified = user.modified_ts
        user.modified_ts = datetime.utcnow()
        if modified is None:
            # profile has never been modified through the dashboard.
            # possibly just created in signup.
            result = self._coll.replace_one(
                {'_id': user.user_id}, user.to_dict(old_userdb_format=old_format), upsert=True
            )
            logger.debug(
                "{!s} Inserted new user {!r} into {!r} (old_format={!r}): {!r})".format(
                    self, user, self._coll_name, old_format, result
                )
            )
            import pprint

            extra_debug = pprint.pformat(user.to_dict(old_userdb_format=old_format))
            logger.debug(f"Extra debug:\n{extra_debug}")
        else:
            test_doc = {'_id': user.user_id}
            if check_sync:
                test_doc['modified_ts'] = modified
            result = self._coll.replace_one(
                test_doc, user.to_dict(old_userdb_format=old_format), upsert=(not check_sync)
            )
            if check_sync and result.modified_count == 0:
                db_ts = None
                db_user = self._coll.find_one({'_id': user.user_id})
                if db_user:
                    db_ts = db_user['modified_ts']
                logger.debug(
                    f"{self} FAILED Updating user {user} (ts {modified}) in {self._coll_name}"
                    f" (old_format={old_format}). ts in db = {db_ts}"
                )
                raise eduid_userdb.exceptions.UserOutOfSync('Stale user object can\'t be saved')
            logger.debug(
                "{!s} Updated user {!r} (ts {!s}) in {!r} (old_format={!r}): {!r}".format(
                    self, user, modified, self._coll_name, old_format, result
                )
            )
            import pprint

            extra_debug = pprint.pformat(user.to_dict(old_userdb_format=old_format))
            logger.debug(f"Extra debug:\n{extra_debug}")
        return result.acknowledged

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
        logger.debug("{!s} Removing user with id {!r} from {!r}".format(self, user_id, self._coll_name))
        return self.remove_document(spec_or_id=user_id)

    def update_user(self, obj_id: ObjectId, operations: Mapping) -> None:
        """
        Update (or insert) a user document in mongodb.

        operations must be a dict with update operators ({'$set': ..., '$unset': ...}).
        https://docs.mongodb.com/manual/reference/operator/update/

        This update method should only be used in the eduid Attribute Manager when
        merging updates from applications into the central eduID userdb.
        """
        logger.debug(
            "{!s} updating user {!r} in {!r} with operations:\n{!s}".format(self, obj_id, self._coll_name, operations)
        )

        query_filter = {'_id': obj_id}

        # Check that the operations dict includes only the whitelisted operations
        whitelisted_operations = ['$set', '$unset']
        bad_operators = [key for key in operations if key not in whitelisted_operations]
        if bad_operators:
            logger.debug(f'Tried to update/insert document: {query_filter} with operations: {operations}')
            error_msg = f'Invalid update operator: {bad_operators}'
            logger.error(error_msg)
            raise eduid_userdb.exceptions.EduIDDBError(error_msg)

        updated_doc = self._coll.find_one_and_update(
            filter=query_filter, update=operations, return_document=ReturnDocument.AFTER, upsert=True
        )
        logger.debug(f'Updated/inserted document: {updated_doc}')

    def get_identity_proofing(self, user):
        """
        Return the proofing urn value

        :param user: The user object
        :type user: User
        """
        al1_urn = 'http://www.swamid.se/policy/assurance/al1'
        al2_urn = 'http://www.swamid.se/policy/assurance/al2'
        user = self.get_user_by_id(user.user_id)
        if user is not None:
            if user.nins.verified.count > 0:
                return al2_urn

        return al1_urn
