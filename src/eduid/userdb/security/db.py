# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 NORDUnet A/S
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
import copy
import logging
from typing import Any, Dict, Mapping, Optional, Union

from eduid.userdb.db import BaseDB
from eduid.userdb.deprecation import deprecated
from eduid.userdb.exceptions import DocumentOutOfSync, MultipleDocumentsReturned
from eduid.userdb.security.state import PasswordResetEmailAndPhoneState, PasswordResetEmailState, PasswordResetState
from eduid.userdb.security.user import SecurityUser
from eduid.userdb.userdb import UserDB
from eduid.userdb.util import utc_now

logger = logging.getLogger(__name__)

__author__ = "lundberg"


class SecurityUserDB(UserDB[SecurityUser]):
    def __init__(self, db_uri: str, db_name: str = "eduid_security", collection: str = "profiles"):
        super().__init__(db_uri, db_name, collection=collection)

    @classmethod
    def user_from_dict(cls, data: Mapping[str, Any]) -> SecurityUser:
        return SecurityUser.from_dict(data)


# @deprecated("Remove once the password reset views are served from their own webapp")
class PasswordResetStateDB(BaseDB):
    @deprecated("Remove once the password reset views are served from their own webapp")
    def __init__(self, db_uri, db_name="eduid_security", collection="password_reset_data"):
        super(PasswordResetStateDB, self).__init__(db_uri, db_name, collection=collection)

    def get_state_by_email_code(self, email_code: str) -> Optional[PasswordResetState]:
        """
        Locate a state in the db given the state's email code.

        :param email_code: Code sent to the user

        :return: state, if found

        :raise self.MultipleDocumentsReturned: More than one document matches the search criteria
        """
        spec = {"email_code.code": email_code}
        states = list(self._get_documents_by_filter(spec))

        if len(states) == 0:
            return None

        if len(states) > 1:
            raise MultipleDocumentsReturned("Multiple matching users for filter {!r}".format(filter))

        return self.init_state(states[0])

    def get_state_by_eppn(self, eppn: str) -> Optional[PasswordResetState]:
        """
        Locate a state in the db given the users eppn.

        :param eppn: Users unique eppn

        :return: state, if found

        :raise self.MultipleDocumentsReturned: More than one document matches the search criteria
        """
        state = self._get_document_by_attr("eduPersonPrincipalName", eppn)
        if state:
            return self.init_state(state)
        return None

    @staticmethod
    def init_state(
        data: Mapping[str, Any]
    ) -> Optional[Union[PasswordResetEmailState, PasswordResetEmailAndPhoneState]]:
        _data = dict(copy.deepcopy(data))  # to not modify callers data
        method = _data.pop("method", None)
        if method == "email":
            return PasswordResetEmailState.from_dict(_data)
        if method == "email_and_phone":
            return PasswordResetEmailAndPhoneState.from_dict(_data)
        return None

    def save(self, state: PasswordResetState, check_sync: bool = True) -> None:
        """

        :param state: PasswordResetState object
        :param check_sync: Ensure the document hasn't been updated in the database since it was loaded
        """

        modified = state.modified_ts
        state.modified_ts = utc_now()  # update to current time

        data = state.to_dict()
        # Remember what type of state this is, used when loading state above in init_state()
        if isinstance(state, PasswordResetEmailAndPhoneState):
            data["method"] = "email_and_phone"
        elif isinstance(state, PasswordResetEmailState):
            data["method"] = "email"

        if modified is None:
            # document has never been modified
            # Remove old reset password state
            old_state = self.get_state_by_eppn(state.eppn)
            if old_state:
                self.remove_state(old_state)
            result = self._coll.insert_one(data)
            logging.debug(f"{self} Inserted new state {state} into {self._coll_name}): {result.inserted_id})")
        else:
            test_doc: Dict[str, Any] = {"eduPersonPrincipalName": state.eppn}
            if check_sync:
                test_doc["modified_ts"] = modified
            result = self._coll.replace_one(test_doc, data, upsert=(not check_sync))
            if check_sync and result.matched_count == 0:
                db_ts = None
                db_state = self._coll.find_one({"eduPersonPrincipalName": state.eppn})
                if db_state:
                    db_ts = db_state["modified_ts"]
                logging.debug(
                    "{!s} FAILED Updating state {!r} (ts {!s}) in {!r}). ts in db = {!s}".format(
                        self, state, modified, self._coll_name, db_ts
                    )
                )
                raise DocumentOutOfSync("Stale state object can't be saved")

            logging.debug(
                "{!s} Updated state {!r} (ts {!s}) in {!r}): {!r}".format(
                    self, state, modified, self._coll_name, result
                )
            )

    def remove_state(self, state):
        """
        :param state: ProofingStateClass object

        :type state: ProofingStateClass
        """
        self.remove_document({"eduPersonPrincipalName": state.eppn})
