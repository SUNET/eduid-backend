# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 SUNET
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
from typing import Any, Dict, Mapping, Optional

from eduid_userdb.db import BaseDB
from eduid_userdb.exceptions import DocumentOutOfSync, MultipleDocumentsReturned
from eduid_userdb.reset_password.state import (
    ResetPasswordEmailAndPhoneState,
    ResetPasswordEmailState,
    ResetPasswordState,
)
from eduid_userdb.reset_password.user import ResetPasswordUser
from eduid_userdb.user import User
from eduid_userdb.userdb import UserDB

logger = logging.getLogger(__name__)


class ResetPasswordUserDB(UserDB):

    UserClass = ResetPasswordUser

    def __init__(self, db_uri: Optional[str], db_name: str = 'eduid_reset_password', collection: str = 'profiles'):
        super(ResetPasswordUserDB, self).__init__(db_uri, db_name, collection=collection)

    def save(self, user: User, check_sync: bool = True, old_format: bool = False) -> bool:
        return super(ResetPasswordUserDB, self).save(user, check_sync=check_sync, old_format=old_format)


class ResetPasswordStateDB(BaseDB):
    def __init__(
        self, db_uri: Optional[str], db_name: str = 'eduid_reset_password', collection: str = 'password_reset_data'
    ):
        super(ResetPasswordStateDB, self).__init__(db_uri, db_name, collection=collection)

    def get_state_by_email_code(self, email_code: str, raise_on_missing: bool = True):
        """
        Locate a state in the db given the state's email code.

        :param email_code: Code sent to the user
        :param raise_on_missing: Raise exception if True else return None

        :return: ResetPasswordState instance | None

        :raise self.DocumentDoesNotExist: No document match the search criteria
        :raise self.MultipleDocumentsReturned: More than one document matches
                                               the search criteria
        """
        spec = {'email_code.code': email_code}
        states = list(self._get_documents_by_filter(spec, raise_on_missing=raise_on_missing))

        if len(states) == 0:
            return None

        if len(states) > 1:
            raise MultipleDocumentsReturned(f'Multiple matching users for filter {filter}')

        return self.init_state(states[0])

    def get_state_by_eppn(self, eppn: str, raise_on_missing: bool = True):
        """
        Locate a state in the db given the users eppn.

        :param eppn: Users unique eppn
        :param raise_on_missing: Raise exception if True else return None

        :return: ResetPasswordState instance | None

        :raise self.DocumentDoesNotExist: No document match the search criteria
        :raise self.MultipleDocumentsReturned: More than one document matches
                                               the search criteria
        """
        state = self._get_document_by_attr('eduPersonPrincipalName', eppn, raise_on_missing)
        if state:
            return self.init_state(state)

    @staticmethod
    def init_state(state: Mapping) -> Optional[ResetPasswordState]:
        resetpw_state = None
        if state.get('method') == 'email':
            resetpw_state = ResetPasswordEmailState(data=state)
        if state.get('method') == 'email_and_phone':
            resetpw_state = ResetPasswordEmailAndPhoneState(data=state)
        return resetpw_state

    def save(self, state: ResetPasswordState, check_sync: bool = True):
        """

        :param state: ResetPasswordState object
        :param check_sync: Ensure the document hasn't been updated in the
                           database since it was loaded
        """
        modified = state.modified_ts
        state.modified_ts = True  # update to current time
        if modified is None:
            # document has never been modified
            # Remove old reset password state
            old_state = self.get_state_by_eppn(state.eppn, raise_on_missing=False)
            if old_state:
                self.remove_state(old_state)

            result = self._coll.insert_one(state.to_dict())
            logging.debug(f"{self} Inserted new state {state} into {self._coll_name}): {result.inserted_id})")

        else:
            test_doc: Dict[str, Any] = {'eduPersonPrincipalName': state.eppn}
            if check_sync:
                test_doc['modified_ts'] = modified
            result = self._coll.replace_one(test_doc, state.to_dict(), upsert=(not check_sync))
            if check_sync and result.matched_count == 0:
                db_ts = None
                db_state = self._coll.find_one({'eppn': state.eppn})
                if db_state:
                    db_ts = db_state['modified_ts']
                logging.debug(
                    f'{self} FAILED Updating state {state} (ts {modified}) in {self._coll_name}). ts in db = {db_ts}'
                )
                raise DocumentOutOfSync("Stale state object can't be saved")

            logging.debug(f'{self} Updated state {state} (ts {modified}) in {self._coll_name}): {result}')

    def remove_state(self, state: ResetPasswordState):
        """
        :param state: ResetPasswordState object
        """
        self.remove_document({'eduPersonPrincipalName': state.eppn})
