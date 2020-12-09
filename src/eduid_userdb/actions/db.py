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
from typing import Any, Dict, List, Optional, Tuple, Union

from bson import ObjectId
from bson.errors import InvalidId
from pymongo.cursor import Cursor
from pymongo.results import DeleteResult

from eduid_userdb.actions import Action
from eduid_userdb.db import BaseDB
from eduid_userdb.exceptions import ActionDBError

logger = logging.getLogger(__name__)


class ActionDB(BaseDB):
    """
    Interface class to the central eduID actions DB.
    """

    ActionClass = Action

    def __init__(self, db_uri, db_name='eduid_actions', collection='actions'):
        super(ActionDB, self).__init__(db_uri, db_name, collection)

        logger.debug("{!s} connected to database".format(self))

    def __repr__(self):
        return '<eduID {!s}: {!s} {!r} (returning {!s})>'.format(
            self.__class__.__name__, self._db.sanitized_uri, self._coll_name, self.ActionClass.__name__
        )

    def _read_actions_from_db(
        self,
        eppn_or_userid: Union[str, ObjectId],
        session: Optional[str],
        filter_: Optional[dict] = None,
        match_no_session: bool = True,
    ) -> Tuple[bool, Cursor]:
        old_format = True
        try:
            query = {'user_oid': ObjectId(str(eppn_or_userid))}
        except InvalidId:
            old_format = False
            query = {'eppn': eppn_or_userid}
        if session is not None:
            query['$or'] = [{'session': {'$exists': False}}, {'session': session}]
        if filter_ is not None:
            query.update(filter_)
        return old_format, self._coll.find(query).sort('preference')

    def get_actions(
        self, eppn_or_userid: Union[str, ObjectId], session: Optional[str], action_type: Optional[str] = None
    ) -> List[Action]:
        """
        Check in the db (not in the cache) whether there are actions
        with whatever attributes you feed to the method.
        Used for example when the IdP wants to see if an MFA action it created
        earlier has been updated with an authentication response by the MFA plugin.

        :param eppn_or_userid: The eppn (or user_oid) of the user with possible pending actions
        :param session: The actions session for the user
        :param action_type: The type of action to be performed ('mfa', 'tou', ...)
        """
        _, actions = self._read_actions_from_db(eppn_or_userid, session)

        if action_type is None:
            # Don't filter on action type, return all actions for user(+session)
            return [Action.from_dict(this) for this in actions]
        res = []
        for this in actions:
            if this['action'] == action_type:
                res.append(Action.from_dict(this))
        return res

    def has_actions(
        self,
        eppn_or_userid: Union[str, ObjectId],
        session: Optional[str] = None,
        action_type: Optional[str] = None,
        params: Optional[dict] = None,
    ) -> bool:
        """
        Check in the db (not in the cache) whether there are actions
        with whatever attributes you feed to the method.
        Used for example when adding a new ToU action, to check
        that another app didn't create the action with another session.

        :param eppn_or_userid: The eppn (or id) of the user with possible pending actions
        :param session: The actions session for the user
        :param action_type: The type of action to be performed
        :param params: Extra params specific to the action type
        """
        filter_: Dict[str, Any] = {}
        if action_type is not None:
            filter_['action'] = action_type
        if params is not None:
            filter_['params'] = params

        old_format, actions = self._read_actions_from_db(eppn_or_userid, session, filter_)
        return len(list(actions)) > 0

    def get_next_action(self, eppn_or_userid, session=None):
        """
        Return next pending action for eppn_or_userid and session.
        If session is None, search actions with no session,
        otherwise search actions with either no session
        or with the specified session.
        If there is no pending action, return None

        :param eppn_or_userid: The eppn (or id) of the user with possible pending actions
        :param session: The IdP session for the user

        :type eppn_or_userid: str
        :type session: str

        :rtype: eduid_userdb.actions:Action or None
        """
        filter_ = {'result': None}
        old_format, actions = self._read_actions_from_db(eppn_or_userid, session, filter_)
        for this in actions:
            # return first element in list
            return Action.from_dict(this)
        return None

    def add_action(
        self,
        eppn_or_userid: Optional[Union[str, ObjectId]] = None,
        action_type: Optional[str] = None,
        preference: int = 100,
        session: Optional[str] = None,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
    ) -> Action:
        """
        Add an action to the DB.

        :param eppn_or_userid: The eppn (or id) of the user who has to perform the action
        :param action_type: the kind of action to be performed
        :param preference: preference to order actions
        :param session: The IdP session for the user
        :param params: Any params the action may need
        :param data: all the previous params together
        :returns: Added action
        """
        if data is None:
            data = {
                'action': action_type,
                'preference': preference,
            }
            if isinstance(eppn_or_userid, ObjectId):
                data['user_oid'] = eppn_or_userid
            else:
                data['eppn'] = eppn_or_userid
            if session is not None:
                data['session'] = session
            if params is not None:
                data['params'] = params

        # XXX deal with exceptions here ?
        action = Action.from_dict(data)
        result = self._coll.insert_one(action.to_dict())
        if result.acknowledged:
            return action
        logger.error("Failed inserting action {!r} into db".format(action))
        raise ActionDBError('Failed inserting action into db')

    def update_action(self, action):
        """
        Write an updated action to the database.

        :param action: The action to update

        :type action: Action
        :rtype: None
        """
        result = self._coll.replace_one({'_id': action.action_id}, action.to_dict())
        if result.modified_count:
            logger.debug('Updated action {} in the db: {}'.format(action, result))
            return
        logger.error('Failed updating action {} in db: {}'.format(action, result))
        raise ActionDBError('Failed updating action in db')

    def remove_action_by_id(self, action_id: ObjectId) -> bool:
        """
        Remove an action in the actions db given the action's _id.

        :param action_id: Action id
        """
        logger.debug("{!s} Removing action with id {!r} from {!r}".format(self, action_id, self._coll_name))
        result = self._coll.delete_one({'_id': action_id})
        return result.acknowledged
