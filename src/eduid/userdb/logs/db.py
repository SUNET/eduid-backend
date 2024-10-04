import logging
from datetime import datetime
from uuid import UUID

from eduid.userdb.db import BaseDB, TUserDbDocument
from eduid.userdb.logs.element import LogElement, UserChangeLogElement

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class LogDB(BaseDB):
    def __init__(self, db_uri: str, collection: str) -> None:
        db_name = "eduid_logs"
        # Make sure writes reach a majority of replicas
        super().__init__(db_uri, db_name, collection, safe_writes=True)

    def _insert(self, doc: TUserDbDocument) -> None:
        self._coll.insert_one(doc)

    def save(self, log_element: LogElement) -> bool:
        """
        :param log_element: The log element to save
        :return: True on success
        """
        self._insert(log_element.to_dict())
        return True


class ProofingLog(LogDB):
    def __init__(self, db_uri: str, collection: str = "proofing_log") -> None:
        super().__init__(db_uri, collection)


class FidoMetadataLog(LogDB):
    def __init__(self, db_uri: str, collection: str = "fido_metadata_log") -> None:
        super().__init__(db_uri, collection)
        # Create an index so that metadata logs are unique for authenticator id and last status change datetime
        indexes = {
            "unique-id-date": {"key": [("authenticator_id", 1), ("last_status_change", 1)], "unique": True},
        }
        self.setup_indexes(indexes)

    def exists(self, authenticator_id: str | UUID, last_status_change: datetime) -> bool:
        return bool(
            self.db_count(
                spec={"authenticator_id": authenticator_id, "last_status_change": last_status_change},
                limit=1,
            )
        )


class UserChangeLog(LogDB):
    def __init__(self, db_uri: str, collection: str = "user_change_log") -> None:
        super().__init__(db_uri, collection)

    def get_by_eppn(self, eppn: str) -> list[UserChangeLogElement]:
        docs = self._get_documents_by_attr("eduPersonPrincipalName", eppn)
        return [UserChangeLogElement(**doc) for doc in docs]


class ManagedAccountLog(LogDB):
    def __init__(self, db_uri: str, collection: str = "managed_account_log") -> None:
        super().__init__(db_uri, collection)
        # Create in index
        indexes = {"expiration-time": {"key": [("expire_at", 1)], "expireAfterSeconds": 0}}
        self.setup_indexes(indexes)
