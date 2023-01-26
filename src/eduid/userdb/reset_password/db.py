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
from typing import Any, Mapping, Optional, Union

from eduid.userdb.db import BaseDB, SaveResult, TUserDbDocument
from eduid.userdb.exceptions import MultipleDocumentsReturned
from eduid.userdb.reset_password.state import (
    ResetPasswordEmailAndPhoneState,
    ResetPasswordEmailState,
    ResetPasswordState,
)
from eduid.userdb.reset_password.user import ResetPasswordUser
from eduid.userdb.userdb import UserDB

logger = logging.getLogger(__name__)


class ResetPasswordUserDB(UserDB[ResetPasswordUser]):
    def __init__(self, db_uri: str, db_name: str = "eduid_reset_password", collection: str = "profiles"):
        super().__init__(db_uri, db_name, collection=collection)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> ResetPasswordUser:
        return ResetPasswordUser.from_dict(data)


class ResetPasswordStateDB(BaseDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_reset_password", collection: str = "password_reset_data"):
        super().__init__(db_uri, db_name, collection=collection)

    def get_state_by_email_code(
        self, email_code: str
    ) -> Optional[Union[ResetPasswordEmailState, ResetPasswordEmailAndPhoneState]]:
        """
        Locate a state in the db given the state's email code.

        :param email_code: Code sent to the user

        :return: ResetPasswordState subclass instance

        :raise self.DocumentDoesNotExist: No document match the search criteria
        :raise self.MultipleDocumentsReturned: More than one document matches
                                               the search criteria
        """
        spec = {"email_code.code": email_code}
        states = list(self._get_documents_by_filter(spec))

        if len(states) == 0:
            return None

        if len(states) > 1:
            raise MultipleDocumentsReturned(f"Multiple matching users for filter {filter}")

        return self.init_state(states[0])

    def get_state_by_eppn(self, eppn: str) -> Optional[Union[ResetPasswordEmailState, ResetPasswordEmailAndPhoneState]]:
        """
        Locate a state in the db given the users eppn.

        :param eppn: Users unique eppn

        :return: ResetPasswordState subclass instance

        :raise self.MultipleDocumentsReturned: More than one document matches the search criteria
        """
        state = self._get_document_by_attr("eduPersonPrincipalName", eppn)
        if state:
            return self.init_state(state)
        return None

    @staticmethod
    def init_state(state_mapping: Mapping) -> Optional[Union[ResetPasswordEmailState, ResetPasswordEmailAndPhoneState]]:
        state = dict(state_mapping)
        if state.get("method") == "email":
            return ResetPasswordEmailState.from_dict(data=state)
        elif state.get("method") == "email_and_phone":
            return ResetPasswordEmailAndPhoneState.from_dict(data=state)
        return None

    def save(self, state: ResetPasswordState, is_in_database: bool = True) -> SaveResult:
        """
        Save state to the database.

        :param is_in_database: Whether the state is already in the database or not
        """
        if state.modified_ts is None:
            # Remove old reset password state
            old_state = self.get_state_by_eppn(state.eppn)
            if old_state:
                self.remove_state(old_state)

        spec: dict[str, Any] = {"eduPersonPrincipalName": state.eppn}

        result = self._save(state.to_dict(), spec, is_in_database=is_in_database)
        state.modified_ts = result.ts

        return result

    def remove_state(self, state: ResetPasswordState) -> None:
        """
        :param state: ResetPasswordState object
        """
        self.remove_document({"eduPersonPrincipalName": state.eppn})
