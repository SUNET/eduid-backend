import logging
from collections.abc import Mapping
from typing import Any, Optional, Union

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
