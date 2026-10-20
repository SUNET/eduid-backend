import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.db import BaseDB
from eduid.userdb.element import Element, ElementKey
from eduid.userdb.identity import IdentityType

logger = logging.getLogger(__name__)


class IdentityAgeNotification(Element):
    """
    Record of notifications sent (and actions taken) for one verification of one identity of a user.

    A re-verified identity has a new verified_at and thus gets a new record.

    created_ts is when the record was first written, modified_ts when it was last changed.

    Records are removed automatically (MongoDB TTL index on modified_ts) once they have not been
    modified for the auto_expire period, see IdentityAgeNotificationDB.
    """

    eppn: str
    identity_type: IdentityType
    verified_at: datetime
    warning_sent_ts: datetime | None = None
    unverified_ts: datetime | None = None

    @property
    def key(self) -> ElementKey:
        """
        Unique per verification of an identity (within one user): identity type and verified_at (UTC, ms precision).
        """
        verified_at = IdentityAgeNotificationDB.normalise_verified_at(self.verified_at)
        return ElementKey(f"{self.identity_type.value}:{verified_at.isoformat(timespec='milliseconds')}")


class IdentityAgeNotificationDB(BaseDB):
    """
    Database of IdentityAgeNotification records.

    Records are auto-removed by MongoDB (TTL index on modified_ts) after `auto_expire` without modification.
    Every write goes through _update which sets modified_ts (a BSON date, as required by TTL indexes).
    The TTL monitor runs about once a minute, so removal is not instantaneous.

    auto_expire is required here; the default lives in the configuration (IdentityAgeConfig).

    Unlike the fixed index name idiom used elsewhere (e.g. UserDB, ProofingStateDB), the auto_expire seconds are
    part of the TTL index name. BaseDB.setup_indexes ignores changed options of an existing index name, so with
    a fixed name a changed config would never take effect. With the seconds in the name, changing auto_expire
    creates a new index and drops the old one.
    """

    def __init__(
        self,
        db_uri: str,
        auto_expire: timedelta,
        db_name: str = "eduid_job_runner",
        collection: str = "identity_age_notifications",
    ) -> None:
        super().__init__(db_uri, db_name, collection)

        expire_seconds = int(auto_expire.total_seconds())
        if expire_seconds < 1:
            raise ValueError("auto_expire must be at least one second")

        indexes = {
            f"auto-discard-modified-ts-{expire_seconds}s": {
                "key": [("modified_ts", 1)],
                "expireAfterSeconds": expire_seconds,
            },
            "eppn-identity-verified-at-index-v1": {
                "key": [("eppn", 1), ("identity_type", 1), ("verified_at", 1)],
                "unique": True,
            },
        }
        self.setup_indexes(indexes)

    @staticmethod
    def normalise_verified_at(verified_at: datetime) -> datetime:
        """
        Normalise verified_at to what is stored in MongoDB: UTC, timezone aware, millisecond precision.

        Used for every lookup and upsert so that the key always matches. Naive datetimes are assumed to be UTC.
        """
        if verified_at.tzinfo is None:
            verified_at = verified_at.replace(tzinfo=UTC)
        verified_at = verified_at.astimezone(UTC)
        return verified_at.replace(microsecond=verified_at.microsecond // 1000 * 1000)

    @classmethod
    def _spec(cls, eppn: str, identity_type: IdentityType, verified_at: datetime) -> dict[str, Any]:
        return {
            "eppn": eppn,
            "identity_type": identity_type.value,
            "verified_at": cls.normalise_verified_at(verified_at),
        }

    def _update(
        self,
        eppn: str,
        identity_type: IdentityType,
        verified_at: datetime,
        set_fields: dict[str, Any] | None = None,
        unset: list[str] | None = None,
        upsert: bool = True,
    ) -> None:
        """
        Update (or create) the record, always advancing modified_ts and setting created_ts on insert.
        """
        now = utc_now()
        update: dict[str, Any] = {
            "$set": {**(set_fields or {}), "modified_ts": now},
            "$setOnInsert": {"created_ts": now},
        }
        if unset:
            update["$unset"] = dict.fromkeys(unset, "")
        self._coll.update_one(self._spec(eppn, identity_type, verified_at), update, upsert=upsert)

    def get(self, eppn: str, identity_type: IdentityType, verified_at: datetime) -> IdentityAgeNotification | None:
        """
        :returns: The notification record for this verification of the identity, if any
        """
        doc = self._coll.find_one(self._spec(eppn, identity_type, verified_at))
        if doc is None:
            return None
        doc.pop("_id", None)
        return IdentityAgeNotification.from_dict(doc)

    def has_warning(self, eppn: str, identity_type: IdentityType, verified_at: datetime) -> bool:
        """
        :returns: True if a warning has been recorded as sent for this verification of the identity
        """
        notification = self.get(eppn, identity_type, verified_at)
        return notification is not None and notification.warning_sent_ts is not None

    def mark_warned(
        self,
        eppn: str,
        identity_type: IdentityType,
        verified_at: datetime,
        warning_sent_ts: datetime | None = None,
    ) -> None:
        """
        Record that a warning is being sent. This is written before the mail is queued, see clear_warning.
        """
        self._update(eppn, identity_type, verified_at, {"warning_sent_ts": warning_sent_ts or utc_now()}, upsert=True)

    def clear_warning(self, eppn: str, identity_type: IdentityType, verified_at: datetime) -> None:
        """
        Roll back mark_warned when no mail could be queued, so the warning is retried on the next run.
        """
        self._update(eppn, identity_type, verified_at, unset=["warning_sent_ts"], upsert=False)

    def mark_unverified(self, eppn: str, identity_type: IdentityType, verified_at: datetime) -> None:
        """
        Record that the identity has been unverified.
        """
        self._update(eppn, identity_type, verified_at, {"unverified_ts": utc_now()}, upsert=True)
