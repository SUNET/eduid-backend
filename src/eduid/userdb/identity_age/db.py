import logging
from collections.abc import Iterator
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
    # Set before an unverification is synced to the central db and cleared when it is recorded (unverified_ts) or
    # known not to have landed. A record with this set and no unverified_ts is pending work to reconcile, even if
    # the identity is no longer verified centrally.
    unverify_requested_ts: datetime | None = None
    # Set before the warning mail is queued and cleared, together with setting warning_sent_ts, once at least one
    # mail was queued. A record with this set and no warning_sent_ts is a warning to retry. warning_sent_ts is
    # never set without a queued mail, so it can be trusted as proof that the user had notice.
    warning_requested_ts: datetime | None = None
    # Set together with unverified_ts when the user is to be told about the unverification, and cleared (setting
    # notice_sent_ts) once at least one notice mail was queued. A record with this set is a notice to retry, even if
    # the user has no verified identity left.
    notice_requested_ts: datetime | None = None
    notice_sent_ts: datetime | None = None

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
            # Sparse: only records with a pending unverification are indexed, see iter_pending_unverifications
            "unverify-requested-index-v1": {
                "key": [("unverify_requested_ts", 1)],
                "sparse": True,
            },
            # Sparse: only records with a pending warning or notice are indexed, see iter_pending_warnings and
            # iter_pending_notices
            "warning-requested-index-v1": {
                "key": [("warning_requested_ts", 1)],
                "sparse": True,
            },
            "notice-requested-index-v1": {
                "key": [("notice_requested_ts", 1)],
                "sparse": True,
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

    def mark_warning_requested(
        self,
        eppn: str,
        identity_type: IdentityType,
        verified_at: datetime,
        requested_ts: datetime | None = None,
    ) -> None:
        """
        Phase 1 of a warning: record that the warning mail is about to be queued. warning_sent_ts is NOT set, see
        mark_warned.
        """
        self._update(eppn, identity_type, verified_at, {"warning_requested_ts": requested_ts or utc_now()}, upsert=True)

    def clear_warning_requested(self, eppn: str, identity_type: IdentityType, verified_at: datetime) -> None:
        """
        Remove the pending warning marker without recording a warning, e.g. when there is nothing to warn about.
        """
        self._update(eppn, identity_type, verified_at, unset=["warning_requested_ts"], upsert=False)

    def mark_warned(
        self,
        eppn: str,
        identity_type: IdentityType,
        verified_at: datetime,
        warning_sent_ts: datetime | None = None,
    ) -> None:
        """
        Final phase of a warning: record that a warning mail was queued and clear the pending marker, in one
        atomic update. Must only be called after at least one mail was queued.
        """
        self._update(
            eppn,
            identity_type,
            verified_at,
            {"warning_sent_ts": warning_sent_ts or utc_now()},
            unset=["warning_requested_ts"],
            upsert=True,
        )

    def iter_pending_warnings(self, eppn: str | None = None) -> Iterator[IdentityAgeNotification]:
        """
        :param eppn: only return records of this user
        :returns: records with a warning requested but not recorded as sent
        """
        spec: dict[str, Any] = {
            "warning_requested_ts": {"$exists": True, "$ne": None},
            "warning_sent_ts": None,
            "unverified_ts": None,
        }
        return self._iter(spec, eppn)

    def mark_unverified(
        self, eppn: str, identity_type: IdentityType, verified_at: datetime, notice_requested: bool = False
    ) -> None:
        """
        Record that the identity has been unverified.

        :param notice_requested: also record, in the same update, that the user is to be told about it (see
            mark_notice_sent)
        """
        set_fields: dict[str, Any] = {"unverified_ts": utc_now()}
        if notice_requested:
            set_fields["notice_requested_ts"] = utc_now()
        self._update(
            eppn,
            identity_type,
            verified_at,
            set_fields,
            unset=["unverify_requested_ts"],
            upsert=True,
        )

    def mark_notice_sent(self, eppn: str, identity_type: IdentityType, verified_at: datetime) -> None:
        """
        Record that the unverified notice was queued and clear the pending marker, in one atomic update.
        """
        self._update(
            eppn,
            identity_type,
            verified_at,
            {"notice_sent_ts": utc_now()},
            unset=["notice_requested_ts"],
            upsert=False,
        )

    def clear_notice_requested(self, eppn: str, identity_type: IdentityType, verified_at: datetime) -> None:
        """
        Remove the pending notice marker without recording a notice, when no notice is required or possible.
        """
        self._update(eppn, identity_type, verified_at, unset=["notice_requested_ts"], upsert=False)

    def iter_pending_notices(self, eppn: str | None = None) -> Iterator[IdentityAgeNotification]:
        """
        :param eppn: only return records of this user
        :returns: records of unverifications whose notice was requested but not recorded as sent
        """
        return self._iter({"notice_requested_ts": {"$exists": True, "$ne": None}}, eppn)

    def mark_unverify_requested(
        self,
        eppn: str,
        identity_type: IdentityType,
        verified_at: datetime,
        requested_ts: datetime | None = None,
    ) -> None:
        """
        Record that an unverification is about to be synced to the central db. This is written before the sync
        so that the outcome can be reconciled later even if the job fails after the change was applied.
        """
        self._update(
            eppn, identity_type, verified_at, {"unverify_requested_ts": requested_ts or utc_now()}, upsert=True
        )

    def clear_unverify_requested(self, eppn: str, identity_type: IdentityType, verified_at: datetime) -> None:
        """
        Remove the pending marker, e.g. when the unverification is known not to have landed.
        """
        self._update(eppn, identity_type, verified_at, unset=["unverify_requested_ts"], upsert=False)

    def iter_pending_unverifications(self, eppn: str | None = None) -> Iterator[IdentityAgeNotification]:
        """
        :param eppn: only return records of this user
        :returns: records with an unverification requested but not recorded as done
        """
        spec: dict[str, Any] = {"unverify_requested_ts": {"$exists": True, "$ne": None}, "unverified_ts": None}
        return self._iter(spec, eppn)

    def _iter(self, spec: dict[str, Any], eppn: str | None) -> Iterator[IdentityAgeNotification]:
        if eppn is not None:
            spec["eppn"] = eppn
        for doc in self._coll.find(spec):
            doc.pop("_id", None)
            yield IdentityAgeNotification.from_dict(doc)
