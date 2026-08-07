import logging
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from pymongo import ReturnDocument

from eduid.userdb.db import BaseDB, SaveResult, TUserDbDocument
from eduid.userdb.reset_password.state import (
    ResetPasswordEmailAndPhoneState,
    ResetPasswordEmailState,
    ResetPasswordState,
)
from eduid.userdb.reset_password.user import ResetPasswordUser
from eduid.userdb.userdb import AutoExpiringUserDB

logger = logging.getLogger(__name__)


class ResetPasswordUserDB(AutoExpiringUserDB[ResetPasswordUser]):
    def __init__(
        self,
        db_uri: str,
        db_name: str = "eduid_reset_password",
        collection: str = "profiles",
        auto_expire: timedelta | None = None,
    ) -> None:
        super().__init__(db_uri, db_name, collection=collection, auto_expire=auto_expire)

    @classmethod
    def user_from_dict(cls, data: TUserDbDocument) -> ResetPasswordUser:
        return ResetPasswordUser.from_dict(data)


class ResetPasswordStateDB(BaseDB):
    def __init__(
        self,
        db_uri: str,
        db_name: str = "eduid_reset_password",
        collection: str = "password_reset_data",
        auto_expire: timedelta | None = None,
    ) -> None:
        super().__init__(db_uri, db_name, collection=collection)
        if auto_expire is not None:
            # auto expire old state data
            indexes = {
                "auto-discard-modified-ts": {
                    "key": [("modified_ts", 1)],
                    "expireAfterSeconds": int(auto_expire.total_seconds()),
                },
            }
            self.setup_indexes(indexes)

    def get_state_by_eppn(self, eppn: str) -> ResetPasswordEmailState | ResetPasswordEmailAndPhoneState | None:
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
    def init_state(
        state_mapping: Mapping[str, Any],
    ) -> ResetPasswordEmailState | ResetPasswordEmailAndPhoneState | None:
        state = dict(state_mapping)
        if state.get("method") == "email":
            return ResetPasswordEmailState.from_dict(data=state)
        elif state.get("method") == "email_and_phone":
            return ResetPasswordEmailAndPhoneState.from_dict(data=state)
        return None

    def reserve_bad_attempt(self, state: ResetPasswordState, max_attempts: int) -> int | None:
        """
        Reserve one email code submission against a state, if the state has any left.

        The cap check and the increment are a single atomic update because they are a single
        decision: a check done separately is stale the moment it returns, so parallel guesses
        would all read the same count, all pass the check, and all get to compare a different
        code before any of them is counted - letting a correct guess through after the cap was
        already spent. Callers must reserve first, and reject a submission that cannot reserve.

        The update is done in the database rather than through save(), which would be a
        read-check-write across the whole request: save() filters replace_one on the
        modified_ts the caller loaded, so two requests that loaded the same state would have
        one of them lose its increment and raise DocumentOutOfSync. $inc also deliberately
        leaves modified_ts untouched, so an attempt neither re-arms the resend throttle nor
        postpones the auto-expire index.

        :param state: the state to reserve an attempt against, updated in place
        :param max_attempts: incorrect submissions allowed per state, from the app config
        :return: the number of attempts recorded for the state, this one included, or None if
                 nothing could be reserved because the state is locked or no longer exists
        """
        doc = self._coll.find_one_and_update(
            filter={
                "eduPersonPrincipalName": state.eppn,
                # States written before the counter existed carry no field at all, and $lt does
                # not match a missing field - without the $exists arm they would be locked out
                # permanently instead of starting from zero.
                "$or": [{"bad_attempts": {"$lt": max_attempts}}, {"bad_attempts": {"$exists": False}}],
            },
            update={"$inc": {"bad_attempts": 1}},
            return_document=ReturnDocument.AFTER,
            # No upsert: a state removed while the request was in flight must stay removed.
        )
        if doc is None:
            logger.debug(f"No email code attempt could be reserved for {state.eppn}")
            return None
        state.bad_attempts = int(doc["bad_attempts"])
        return state.bad_attempts

    def reset_bad_attempts(self, state: ResetPasswordState) -> None:
        """
        Clear the incorrect email code counter for a state, after the correct code was supplied.

        Written straight to the database for the same reasons as reserve_bad_attempt: save()
        filters replace_one on the modified_ts the caller loaded, so a concurrent write would
        turn this into a DocumentOutOfSync. $set also deliberately leaves modified_ts alone, so
        clearing the counter neither re-arms the resend throttle nor postpones the auto-expire
        index.

        :param state: the state to clear the counter on, updated in place
        """
        result = self._coll.update_one(
            filter={"eduPersonPrincipalName": state.eppn},
            update={"$set": {"bad_attempts": 0}},
            # No upsert: a state removed while the request was in flight must stay removed.
        )
        if result.matched_count == 0:
            logger.debug(f"No reset password state left to clear the bad attempt counter on: {state.eppn}")
        # Set in memory regardless of whether a document was matched. The caller has proven it
        # holds the code, so zero is the right value for anything downstream that re-saves the
        # state - notably the phone-expiry rebuild, which would otherwise persist a stale count.
        state.bad_attempts = 0

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
