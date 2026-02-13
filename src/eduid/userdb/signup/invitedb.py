import logging
from dataclasses import replace
from typing import Any

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.db import SaveResult
from eduid.userdb.exceptions import MultipleDocumentsReturned
from eduid.userdb.signup import Invite, SCIMReference
from eduid.userdb.signup.invite import InviteReference
from eduid.userdb.userdb import BaseDB

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class SignupInviteDB(BaseDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_signup", collection: str = "invites") -> None:
        BaseDB.__init__(self, db_uri, db_name, collection)
        # Create an index so that invite_code is unique and invites are removed at the expires_at time
        indexes = {
            "unique-invite-code": {"key": [("invite_code", 1)], "unique": True},
            "auto-discard-expires-at": {
                "key": [("expires_at", 1)],
                "expireAfterSeconds": 0,
            },
        }
        self.setup_indexes(indexes)

    def get_invite_by_invite_code(self, code: str) -> Invite | None:
        doc = self._get_document_by_attr("invite_code", code)
        if doc:
            return Invite.from_dict(doc)
        return None

    def get_invite_by_reference(self, reference: InviteReference) -> Invite | None:
        if isinstance(reference, SCIMReference):
            spec = {"invite_reference.scim_id": reference.scim_id, "invite_reference.data_owner": reference.data_owner}
        else:
            raise NotImplementedError(f"Reference of type {type(reference)} not implemented.")
        docs = self._get_documents_by_filter(spec=spec)
        if len(docs) > 1:
            raise MultipleDocumentsReturned(f"Multiple matching documents for {spec!r}")
        elif len(docs) == 1:
            return Invite.from_dict(docs[0])
        return None

    def save(self, invite: Invite, is_in_database: bool) -> SaveResult:
        """
        :param invite: Invite object
        :param is_in_database: True if the invite is already in the database. TODO: Remove when invites have Meta.
        """
        spec: dict[str, Any] = {"_id": invite.invite_id}

        result = self._save(invite.to_dict(), spec, is_in_database=is_in_database)
        invite = replace(invite, modified_ts=utc_now())  # update to current time

        return result
