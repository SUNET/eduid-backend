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
import pymongo

from eduid_userdb.actions import Action
from eduid_userdb.db import BaseDB
from eduid_userdb.exceptions import ActionDBError

import logging
logger = logging.getLogger(__name__)


class ActionDB(BaseDB):
    """
    Interface class to the central eduID actions DB.
    """

    ActionClass = Action

    def __init__(self, db_uri, db_name='eduid_actions', collection='actions'):
        super(ActionDB, self).__init__(db_uri, db_name, collection)

        self._cache = {}
        logger.debug("{!s} connected to database".format(self))

    def __repr__(self):
        return '<eduID {!s}: {!s} {!r} (returning {!s})>'.format(self.__class__.__name__,
                                                                 self._db.sanitized_uri,
                                                                 self._coll_name,
                                                                 self.ActionClass.__name__)

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
        :param session: The actions session for the user

        :type userid: str
        :type session: str
        """
        cachekey = self._make_key(userid, session)
        if cachekey in self._cache:
            del self._cache[cachekey]

    def _update_cache(self, userid, session):
        cachekey = self._make_key(userid, session)

        if cachekey not in self._cache:
            query = {'user_oid': ObjectId(userid)}
            if session is None:
                query['session'] = {'$exists': False}
            else:
                query['$or'] = [ {'session': {'$exists': False}},
                                 {'session': session} ]

            actions = self._coll.find(query).sort('preference')
            count = actions.count()
            if count > 0:
                self._cache[cachekey] = [a for a in actions]
        return cachekey

    def has_pending_actions(self, userid, session=None, clean_cache=False):
        """
        Find out whether the user has pending actions.
        If session is None, search actions with no session,
        otherwise search actions with either no session
        or with the specified session.

        :param userid: The id of the user with possible pending actions
        :param session: The actions session for the user
        :param clean_cache: Whether to clean the cache of pending actions
                            When the IdP finds pending actions, it
                            redirects to the actions app that takes care of
                            them, and does not want to keep them in its own
                            cache.

        :type userid: str
        :type session: str
        :type clean_cache: bool

        :rtype: bool
        """
        cachekey = self._update_cache(userid, session)
        if cachekey in self._cache:
            if len(self._cache[cachekey]) > 0:
                if clean_cache:
                    self.clean_cache(userid, session)
                return True
            else:
                self.clean_cache(userid, session)
        return False

    def has_actions(self, userid=None, session=None, action_type=None, params=None):
        """
        Check in the db (not in the cache) whether there are actions
        with whatever attributes you feed to the method.
        Used for example when adding a new ToU action, to check
        that another app didn't create the action with another session.

        :param userid: The id of the user with possible pending actions
        :param session: The actions session for the user
        :param action_type: The type of action to be performed
        :param params: Extra params specific to the action type

        :type userid: str
        :type session: str
        :type action_type: str
        :type params: dict

        :rtype: bool
        """
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
        :param session: The IdP session for the user

        :type userid: str
        :type session: str

        :rtype: eduid_userdb.actions:Action or None
        """
        cachekey = self._update_cache(userid, session)
        action = None
        if cachekey in self._cache:
            try:
                action_doc = self._cache[cachekey].pop()
            except IndexError:
                self.clean_cache(userid, session)
            else:
                action = Action(data=action_doc)
        return action

    def add_action(self, userid=None, action_type=None, preference=100,
                   session=None, params=None, data=None):
        """
        Add an action to the DB.

        :param userid: The id of the user who has to perform the action
        :param action_type: the kind of action to be performed
        :param preference: preference to order actions
        :param session: The IdP session for the user
        :param params: Any params the action may need
        :param data: all the previous params together

        :type userid: bson.ObjectId
        :type action_type: str
        :type preference: int
        :type session: str
        :type params: dict
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
        action = Action(data = data)
        result = self._coll.insert(action.to_dict())
        if result == action.action_id:
            return action
        logger.error("Failed inserting action {!r} into db".format(action))
        raise ActionDBError('Failed inserting action into db')

    def remove_action_by_id(self, action_id):
        """
        Remove an action in the actions db given the action's _id.

        :param action_id: Action id
        :type action_id: bson.ObjectId
        """
        logger.debug("{!s} Removing action with id {!r} from {!r}".format(self, action_id, self._coll_name))
        return self._coll.remove(spec_or_id=action_id)

