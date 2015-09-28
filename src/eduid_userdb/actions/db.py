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

from eduid_userdb.actions import Action
from eduid_userdb.db import MongoDB

import logging
logger = logging.getLogger(__name__)


class ActionDB(object):
    """
    Interface class to the central eduID actions DB.
    """

    ActionClass = Action

    def __init__(self, db_uri, db_name='eduid_actions',
                               collection='actions', **kwargs):

        self._db_uri = db_uri
        self._coll_name = collection
        if 'replicaSet' in kwargs and kwargs['replicaSet'] is None:
            del kwargs['replicaSet']
        self._db = MongoDB(db_uri, db_name=db_name, **kwargs)
        self._coll = self._db.get_collection(collection)
        self._cache = {}
        logger.debug("{!s} connected to database".format(self, self._db.sanitized_uri, self._coll_name))

    def __repr__(self):
        return '<eduID {!s}: {!s} {!r} (returning {!s})>'.format(self.__class__.__name__,
                                                                 self._db.sanitized_uri,
                                                                 self._coll_name,
                                                                 self.ActionClass.__name__,
                                                                )

    def _make_key(self, userid, session):
        if session is None:
            return userid
        return userid + session

    def clean_cache(self, userid, session=None):
        """
        Delete cache for userid and IdP session.
        Called at the start of a session to clean up
        stale caches.

        :param userid: The id of the user with possible pending actions
        :type userid: str
        :param session: The actions session for the user
        :type session: str
        """
        cachekey = self._make_key(userid, session)
        if cachekey in self._cache:
            del self._cache[cachekey]

    def _retrieve_pending_actions(self, userid, session):
        cachekey = self._make_key(userid, session)

        if cachekey not in self._cache:
            query = {'user_oid': ObjectId(userid)}
            if session is None:
                query['session'] = {'$exists': False}
            else:
                query['$or'] = [ {'session': {'$exists': False}},
                                 {'session': session} ]

            actions = self._coll.find(query).sort('precedence')
            if actions.count() > 0:
                self._cache[cachekey] = actions
        return cachekey

    def has_pending_actions(self, userid, session=None):
        """
        Find out whether the user has pending actions.
        If session is None, search actions with no session,
        otherwise search actions with either no session
        or with the specified session.

        :param userid: The id of the user with possible pending actions
        :type userid: str
        :param session: The actions session for the user
        :type session: str

        :rtype: bool
        """
        cachekey = self._retrieve_pending_actions(userid, session)
        if cachekey in self._cache:
            if self._cache[cachekey].count() > 0:
                return True
            else:
                self.clean_cache(userid, session)
        return False

    def has_actions(self, userid=None, session=None,
                        action_type=None, params=None):
        query = {}
        if userid is not None:
            query['user_oid'] = ObjectId(userid)
        if session is not None:
            query['session'] = session
        if action_type is not None:
            query['action'] = action_type
        if params is not None:
            query['params'] = params

        actions = self._coll.find(query)
        return actions.count() > 0

    def get_next_action(self, userid, session=None):
        """
        Return next pending action for userid and session.
        If session is None, search actions with no session,
        otherwise search actions with either no session
        or with the specified session.
        If there is no pending action, return None

        :param userid: The id of the user with possible pending actions
        :type userid: str
        :param session: The IdP session for the user
        :type session: str

        :rtype: eduid_userdb.actions:Action or None
        """
        cachekey = self._retrieve_pending_actions(userid, session)
        action = None
        if cachekey in self._cache:
            try:
                action_doc = self._cache[cachekey].next()
            except StopIteration:
                self.clean_cache(userid, session)
            else:
                action = Action(data=action_doc)
        return action

    def add_action(self, userid=None, action_type=None, preference=100,
                    session=None, params=None, data=None):
        """
        Add an action to the DB.

        :param userid: The id of the user who has to perform the action
        :type userid: str
        :param action_type: the kind of action to be performed
        :type action_type: str
        :param preference: preference to order actions
        :type preference: int
        :param session: The IdP session for the user
        :type session: str
        :param params: Any params the action may need
        :type params: dict
        :param data: all the previous params together
        :type data: dict

        :rtype: Action
        """
        if data is None:
            data = {'user_oid': userid,
                    'action': action_type,
                    'preference': preference,
                    }
            if session is not None:
                data['session'] = session
            if params is not None:
                data['params'] = params

        # XXX deal with exceptions here ?
        action = Action(data)
        result = self._coll.insert(action.to_dict())
        if result == action.action_id:
            return action

    def remove_action_by_id(self, action_id):
        """
        Remove an action in the actions db given the action's _id.

        :param action_id: Action id
        :type action_id: bson.ObjectId
        """
        logger.debug("{!s} Removing action with id {!r} from {!r}".format(self,
                                                                     action_id,
                                                              self._coll_name))
        return self._coll.remove(spec_or_id=action_id)

    def _drop_whole_collection(self):
        """
        Drop the whole collection. Should ONLY be used in testing, obviously.
        :return:
        """
        logging.warning("{!s} Dropping collection {!r}".format(self,
                                                          self._coll_name))
        return self._coll.drop()

    def db_count(self):
        """
        Return number of entries in the database.

        Used in eduid-signup test cases.
        :return: User count
        :rtype: int
        """
        return self._coll.find({}).count()

    def _get_all_docs(self):
        """
        Return all the user documents in the database.

        Used in eduid-dashboard test cases.

        :return: User documents
        :rtype:
        """
        return self._coll.find({})

    def setup_indexes(self, indexes):
        """
        To update an index add a new item in indexes and remove the previous version.
        """
        # indexes={'index-name': {'key': [('key', 1)], 'param1': True, 'param2': False}, }
        # http://docs.mongodb.org/manual/reference/method/db.collection.ensureIndex/
        default_indexes = ['_id_']  # _id_ index can not be deleted from a mongo collection
        current_indexes = self._coll.index_information()
        for name in current_indexes:
            if name not in indexes and name not in default_indexes:
                self._coll.drop_index(name)
        for name, params in indexes.items():
            if name not in current_indexes:
                key = params.pop('key')
                params['name'] = name
                self._coll.ensure_index(key, **params)

