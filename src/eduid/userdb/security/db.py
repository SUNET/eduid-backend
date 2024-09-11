import copy
import logging
from typing import Any, Mapping, Optional, Union

from eduid.userdb.db import BaseDB, SaveResult, TUserDbDocument
from eduid.userdb.deprecation import deprecated
from eduid.userdb.exceptions import MultipleDocumentsReturned
from eduid.userdb.security.state import PasswordResetEmailAndPhoneState, PasswordResetEmailState, PasswordResetState
from eduid.userdb.security.user import SecurityUser
from eduid.userdb.userdb import UserDB

logger = logging.getLogger(__name__)

__author__ = "lundberg"


class SecurityUserDB(UserDB[SecurityUser]):
    def __init__(self, db_uri: str, db_name: str = "eduid_security", collection: str = "profiles"):
        super().__init__(db_uri, db_name, collection=collection)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> SecurityUser:
        return SecurityUser.from_dict(data)


# @deprecated("Remove once the password reset views are served from their own webapp")
class PasswordResetStateDB(BaseDB):
    @deprecated("Remove once the password reset views are served from their own webapp")
    def __init__(self, db_uri, db_name="eduid_security", collection="password_reset_data"):
        super().__init__(db_uri, db_name, collection=collection)

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
            raise MultipleDocumentsReturned(f"Multiple matching users for filter {filter!r}")

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
        data: Mapping[str, Any],
    ) -> Optional[Union[PasswordResetEmailState, PasswordResetEmailAndPhoneState]]:
        _data = dict(copy.deepcopy(data))  # to not modify callers data
        method = _data.pop("method", None)
        if method == "email":
            return PasswordResetEmailState.from_dict(_data)
        if method == "email_and_phone":
            return PasswordResetEmailAndPhoneState.from_dict(_data)
        return None

    def save(self, state: PasswordResetState, is_in_database: bool) -> SaveResult:
        """
        Save state to the database.

        :param state: The state to save
        :param is_in_database: True if the state is already in the database. TODO: Remove when state have Meta.
        """

        data = state.to_dict()
        # Remember what type of state this is, used when loading state above in init_state()
        if isinstance(state, PasswordResetEmailAndPhoneState):
            data["method"] = "email_and_phone"
        elif isinstance(state, PasswordResetEmailState):
            data["method"] = "email"

        if state.modified_ts is None:
            # Remove old reset password state
            old_state = self.get_state_by_eppn(state.eppn)
            if old_state:
                self.remove_state(old_state)

        spec: dict[str, Any] = {"eduPersonPrincipalName": state.eppn}

        result = self._save(state.to_dict(), spec, is_in_database=is_in_database)
        state.modified_ts = result.ts

        return result

    def remove_state(self, state: PasswordResetState) -> None:
        self.remove_document({"eduPersonPrincipalName": state.eppn})
