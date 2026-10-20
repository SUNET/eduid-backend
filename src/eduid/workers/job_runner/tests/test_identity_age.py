import logging
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from bson import ObjectId
from dateutil.relativedelta import relativedelta
from pydantic import ValidationError
from pytest_mock import MockerFixture

from eduid.common.misc.timeutil import utc_now
from eduid.common.stats import AppStats
from eduid.queue.db import QueueItem
from eduid.queue.db.message import MessageDB
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.identity import (
    EIDASIdentity,
    EIDASLoa,
    IdentityElement,
    IdentityList,
    IdentityType,
    NinIdentity,
    PridPersistence,
)
from eduid.userdb.identity_age.db import IdentityAgeNotificationDB
from eduid.userdb.mail import MailAddressList
from eduid.userdb.meta import CleanerType
from eduid.userdb.user import User
from eduid.userdb.user_cleaner.db import CleanerQueueUser
from eduid.userdb.userdb import AmDB, UserSaveResult
from eduid.workers.job_runner.config import IdentityAgeConfig, JobRunnerConfig
from eduid.workers.job_runner.jobs.identity_age import gather_identity_age_users, process_identity_age_users
from eduid.workers.job_runner.testing import CleanerQueueTestCase, MockContext

NIN = IdentityType.NIN
EIDAS = IdentityType.EIDAS


def _verified_at(user: User, identity_type: IdentityType) -> datetime:
    identity = user.identities.find(identity_type.value)
    assert isinstance(identity, IdentityElement)
    assert identity.verified_at is not None
    return identity.verified_at


def _years_ago(years: int, extra_days: int = 0) -> datetime:
    return utc_now() - relativedelta(years=years) - timedelta(days=extra_days)


class TestCheckIdentityAge(CleanerQueueTestCase):
    users = UserFixtures()

    @pytest.fixture(autouse=True)
    def setup(self, setup_cleaner: None, mocker: MockerFixture) -> Iterator[None]:
        self.amdb = AmDB(db_uri=self.mongo_uri)
        self.amdb._drop_whole_collection()
        self.messagedb = MessageDB(db_uri=self.mongo_uri)
        self.messagedb._drop_whole_collection()
        self.identity_age_db = IdentityAgeNotificationDB(db_uri=self.mongo_uri, auto_expire=timedelta(days=3 * 365))
        self.identity_age_db._drop_whole_collection()
        self.identity_age_db = IdentityAgeNotificationDB(
            db_uri=self.mongo_uri, auto_expire=timedelta(days=3 * 365)
        )  # recreate indexes
        self.dry_run_db = IdentityAgeNotificationDB(
            db_uri=self.mongo_uri, auto_expire=timedelta(days=3 * 365), collection="identity_age_notifications_dry_run"
        )
        self.dry_run_db._drop_whole_collection()
        self.dry_run_db = IdentityAgeNotificationDB(
            db_uri=self.mongo_uri, auto_expire=timedelta(days=3 * 365), collection="identity_age_notifications_dry_run"
        )
        self.stats = mocker.MagicMock(spec=AppStats)
        self.save_and_sync = mocker.patch(
            "eduid.workers.job_runner.jobs.identity_age.save_and_sync_user",
            side_effect=lambda context, user, original=None: context.central_db.save(user),
        )
        yield
        self.amdb._drop_whole_collection()
        self.messagedb._drop_whole_collection()
        self.identity_age_db._drop_whole_collection()
        self.dry_run_db._drop_whole_collection()

    def _context(self, dry_run: bool = False, **identity_age: Any) -> MockContext:
        config = JobRunnerConfig(
            app_name="test_job_runner",
            celery={},
            mongo_uri=self.mongo_uri,
            identity_age=IdentityAgeConfig(**identity_age),
        )
        return MockContext(
            central_db=self.amdb,
            cleaner_queue=self.cleaner_queue_db,
            logger=logging.getLogger("test_identity_age"),
            config=config,
            messagedb=self.messagedb,
            identity_age_db=self.identity_age_db,
            identity_age_dry_run_db=self.dry_run_db,
            stats=self.stats,
            dry_run=dry_run,
        )

    def _queue_size(self) -> int:
        return self.cleaner_queue_db._coll.count_documents({"cleaner_type": CleanerType.IDENTITY_AGE})

    def _enqueue(self, eppn: str) -> None:
        """Queue a user directly, bypassing the filtering done by gather"""
        user = self.amdb.get_user_by_eppn(eppn)
        self.cleaner_queue_db.save(
            CleanerQueueUser(eppn=eppn, cleaner_type=CleanerType.IDENTITY_AGE, identities=user.identities)
        )

    def _run(self, context: MockContext | None = None, process_context: MockContext | None = None) -> None:
        """Gather users into the queue and then process the queue until it is empty."""
        context = context or self._context()
        gather_identity_age_users(context)
        process_context = process_context or context
        while self._queue_size() > 0:
            process_identity_age_users(process_context)

    def test_ttl_index_default(self) -> None:
        info = self.identity_age_db._coll.index_information()
        ttl = {name: v for name, v in info.items() if "expireAfterSeconds" in v}
        assert len(ttl) == 1
        index = next(iter(ttl.values()))
        assert index["key"] == [("modified_ts", 1)]
        assert index["expireAfterSeconds"] == 3 * 365 * 86400

    def test_ttl_index_dry_run_collection(self) -> None:
        info = self.dry_run_db._coll.index_information()
        ttl = [v for v in info.values() if "expireAfterSeconds" in v]
        assert len(ttl) == 1
        assert ttl[0]["key"] == [("modified_ts", 1)]
        assert ttl[0]["expireAfterSeconds"] == 3 * 365 * 86400
        assert self.dry_run_db._coll.name == "identity_age_notifications_dry_run"
        assert self.identity_age_db._coll.name == "identity_age_notifications"

    def test_ttl_index_follows_auto_expire_change(self) -> None:
        db = IdentityAgeNotificationDB(db_uri=self.mongo_uri, auto_expire=timedelta(days=10))
        ttl = [v for v in db._coll.index_information().values() if "expireAfterSeconds" in v]
        assert [v["expireAfterSeconds"] for v in ttl] == [10 * 86400]
        # the unique index is kept
        assert len(db._coll.index_information()) == 3

    def test_invalid_auto_expire(self) -> None:
        with pytest.raises(ValueError, match="at least one second"):
            IdentityAgeNotificationDB(db_uri=self.mongo_uri, auto_expire=timedelta(0))

    def test_modified_ts_is_bson_date_on_all_writes(self) -> None:
        eppn, verified_at = "hubba-bubba", utc_now()
        self.identity_age_db.mark_warned(eppn, IdentityType.NIN, verified_at)
        self.identity_age_db.clear_warning(eppn, IdentityType.NIN, verified_at)
        self.identity_age_db.mark_unverified(eppn, IdentityType.NIN, verified_at)
        doc = self.identity_age_db._coll.find_one({"eppn": eppn})
        assert doc is not None
        assert isinstance(doc["modified_ts"], datetime)

    @staticmethod
    def _nin(
        verified_ts: datetime | None = None, created_ts: datetime | None = None, number: str = "199001011234"
    ) -> NinIdentity:
        return NinIdentity(
            number=number,
            is_verified=True,
            verified_by="test",
            verified_ts=verified_ts,
            created_ts=created_ts or utc_now(),
        )

    @staticmethod
    def _eidas(created_ts: datetime, verified_ts: datetime | None = None) -> EIDASIdentity:
        return EIDASIdentity(
            prid="prid-1",
            prid_persistence=PridPersistence.A,
            loa=EIDASLoa.NF_HIGH,
            country_code="DE",
            date_of_birth=datetime(2000, 1, 1, tzinfo=UTC),
            is_verified=True,
            verified_by="test",
            created_ts=created_ts,
            verified_ts=verified_ts,
        )

    def _save_user(
        self, identities: list[NinIdentity | EIDASIdentity], eppn: str = "hubba-test1", terminated: bool = False
    ) -> User:
        user = self.users.mocked_user_standard.model_copy(deep=True)
        user.eppn = eppn
        user.user_id = ObjectId()
        user.meta.version = ObjectId()
        user.identities = IdentityList(elements=list(identities))
        if terminated:
            user.terminated = utc_now()
        self.amdb.save(user)
        return self.amdb.get_user_by_eppn(eppn)

    def _mails(self) -> list[dict[str, Any]]:
        return list(self.messagedb._coll.find({}))

    def _payload_types(self) -> list[str]:
        return [doc["payload_type"] for doc in self._mails()]

    def _identity(self, eppn: str, identity_type: IdentityType) -> IdentityElement:
        identity = self.amdb.get_user_by_eppn(eppn).identities.find(identity_type.value)
        assert isinstance(identity, IdentityElement)
        return identity

    def _set_warned(
        self, user: User, identity: IdentityElement, days_ago: int, db: IdentityAgeNotificationDB | None = None
    ) -> None:
        assert identity.verified_at is not None
        (db or self.identity_age_db).mark_warned(
            user.eppn,
            identity.identity_type,
            identity.verified_at,
            warning_sent_ts=utc_now() - timedelta(days=days_ago),
        )

    def test_ok_identity_untouched(self) -> None:
        self._save_user([self._nin(verified_ts=_years_ago(1))])
        self._run(self._context())
        assert self._mails() == []
        self.save_and_sync.assert_not_called()

    def test_warn_once_and_idempotent(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        context = self._context()
        self._run(context)
        mails = self._mails()
        # one mail per verified mail address of the user
        assert len(mails) == len(user.mail_addresses.verified) > 0
        assert {m["payload_type"] for m in mails} == {"EduidIdentityExpiryWarningEmail"}
        assert "identity_type" not in mails[0]["payload"]
        assert mails[0]["payload"]["language"] == "en"
        assert self.identity_age_db.has_warning(user.eppn, NIN, _verified_at(user, NIN))
        self.stats.count.assert_any_call("identity_age_warned_nin")

        self._run(context)
        assert len(self._mails()) == len(mails)
        self.save_and_sync.assert_not_called()
        assert self._identity(user.eppn, NIN).is_verified

    def test_foreign_identity_uses_created_ts(self) -> None:
        user = self._save_user([self._eidas(created_ts=_years_ago(4, extra_days=300))])
        self._run(self._context())
        assert self._payload_types()
        assert self.identity_age_db.has_warning(user.eppn, EIDAS, _verified_at(user, EIDAS))

    def test_expired_with_old_warning_unverifies_and_syncs(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])
        assert user.identities.nin is not None
        self._set_warned(user, user.identities.nin, days_ago=31)
        self._run(self._context())

        self.save_and_sync.assert_called_once()
        nin = self._identity(user.eppn, NIN)
        assert nin.is_verified is False
        assert nin.verified_ts is not None
        notification = self.identity_age_db.get(user.eppn, NIN, _verified_at(user, NIN))
        assert notification is not None
        assert notification.unverified_ts is not None
        assert set(self._payload_types()) == {"EduidIdentityUnverifiedEmail"}
        self.stats.count.assert_any_call("identity_age_unverified_nin")

        # a second run does nothing as the identity is no longer verified
        self._run(self._context())
        self.save_and_sync.assert_called_once()

    def test_timestamps_set_and_modified_ts_advances(self) -> None:
        verified_at = _years_ago(5)
        db = self.identity_age_db
        assert db.get("abcd-efgh", NIN, verified_at) is None

        db.mark_warned("abcd-efgh", NIN, verified_at)
        first = db.get("abcd-efgh", NIN, verified_at)
        assert first is not None
        assert first.no_created_ts_in_db is False
        assert first.no_modified_ts_in_db is False
        assert first.created_ts.year > 2000
        assert first.modified_ts >= first.created_ts

        time.sleep(0.01)
        db.mark_unverified("abcd-efgh", NIN, verified_at)
        second = db.get("abcd-efgh", NIN, verified_at)
        assert second is not None
        assert second.created_ts == first.created_ts
        assert second.modified_ts > first.modified_ts
        assert second.unverified_ts is not None

        time.sleep(0.01)
        db.clear_warning("abcd-efgh", NIN, verified_at)
        third = db.get("abcd-efgh", NIN, verified_at)
        assert third is not None
        assert third.warning_sent_ts is None
        assert third.created_ts == first.created_ts
        assert third.modified_ts > second.modified_ts

    def test_concurrent_central_change_is_not_overwritten(self, mocker: MockerFixture) -> None:
        """A change in the central db between load and sync must not be overwritten by the stale snapshot."""
        from eduid.userdb.user_cleaner.userdb import CleanerUserDB
        from eduid.workers.job_runner.helpers import save_and_sync_user as real_save_and_sync_user

        user = self._save_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])
        assert user.identities.nin is not None
        self._set_warned(user, user.identities.nin, days_ago=31)

        context = self._context()
        private_db = CleanerUserDB(db_uri=self.mongo_uri)
        private_db._drop_whole_collection()
        context.private_db = private_db
        am_relay = mocker.MagicMock()
        context.am_relay = am_relay

        def racing_save_and_sync(context: MockContext, user: User, original: User | None = None) -> bool:
            # a webapp verifies an eIDAS identity after the job loaded the user
            central = self.amdb.get_user_by_eppn(user.eppn)
            central.identities.add(self._eidas(created_ts=utc_now(), verified_ts=utc_now()))
            self.amdb.save(central)
            return real_save_and_sync_user(context, user, original=original)

        self.save_and_sync.side_effect = racing_save_and_sync
        self._run(context)

        am_relay.request_user_sync.assert_not_called()
        assert private_db._coll.count_documents({}) == 0
        assert self._identity(user.eppn, NIN).is_verified
        assert self._identity(user.eppn, EIDAS).is_verified
        self.stats.count.assert_any_call("identity_age_failed")
        notification = self.identity_age_db.get(user.eppn, NIN, _verified_at(user, NIN))
        assert notification is not None
        assert notification.unverified_ts is None
        assert self._mails() == []

    def test_unverified_notice_can_be_disabled(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])
        assert user.identities.nin is not None
        self._set_warned(user, user.identities.nin, days_ago=31)
        self._run(self._context(send_unverified_notice=False))
        assert self._identity(user.eppn, NIN).is_verified is False
        assert self._mails() == []

    def test_expired_with_recent_warning_waits(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])
        assert user.identities.nin is not None
        self._set_warned(user, user.identities.nin, days_ago=5)
        self._run(self._context())
        self.save_and_sync.assert_not_called()
        assert self._identity(user.eppn, NIN).is_verified

    def test_expired_without_warning_only_warns(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(6))])
        self._run(self._context())
        self.save_and_sync.assert_not_called()
        assert self._identity(user.eppn, NIN).is_verified
        assert set(self._payload_types()) == {"EduidIdentityExpiryWarningEmail"}
        # the date in the warning is in the future
        expires_at = self._mails()[0]["payload"]["expires_at"]
        assert expires_at >= (utc_now() + timedelta(days=29)).strftime("%Y-%m-%d")

    def test_reverified_user_is_rewarned(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        context = self._context()
        self._run(context)
        first_count = len(self._mails())

        # user verifies again and, much later, it is time to warn again (new verified_at -> new record)
        user = self.amdb.get_user_by_eppn(user.eppn)
        nin = user.identities.nin
        assert nin is not None
        nin.verified_ts = _years_ago(4, extra_days=290)
        self.amdb.save(user)
        self._run(context)
        assert len(self._mails()) == first_count * 2

    def test_no_verified_mail_records_nothing_and_retries(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        saved = self.amdb.get_user_by_eppn(user.eppn)
        original_mails = saved.mail_addresses
        saved.mail_addresses = MailAddressList(elements=[])
        self.amdb.save(saved)
        self._enqueue(user.eppn)
        process_identity_age_users(self._context())
        assert self._mails() == []
        assert not self.identity_age_db.has_warning(user.eppn, NIN, _verified_at(user, NIN))
        assert self.identity_age_db._coll.count_documents({}) == 0
        self.stats.count.assert_any_call("identity_age_no_recipient_nin")

        # user gets a verified mail address: warning goes out on the next run
        saved = self.amdb.get_user_by_eppn(user.eppn)
        saved.mail_addresses = original_mails
        self.amdb.save(saved)
        self._run(self._context())
        assert self._mails()
        assert self.identity_age_db.has_warning(user.eppn, NIN, _verified_at(user, NIN))

    def _remove_mails(self, eppn: str) -> MailAddressList:
        saved = self.amdb.get_user_by_eppn(eppn)
        original_mails = saved.mail_addresses
        saved.mail_addresses = MailAddressList(elements=[])
        self.amdb.save(saved)
        return original_mails

    def test_expired_without_recipient_unverified_immediately(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(6))])
        self._remove_mails(user.eppn)
        self._run(self._context())
        self.save_and_sync.assert_called_once()
        assert self._identity(user.eppn, NIN).is_verified is False
        assert self._mails() == []
        notification = self.identity_age_db.get(user.eppn, NIN, _verified_at(user, NIN))
        assert notification is not None
        assert notification.unverified_ts is not None
        assert notification.warning_sent_ts is None
        self.stats.count.assert_any_call("identity_age_unverified_nin")
        self.stats.count.assert_any_call("identity_age_unverified_no_recipient_nin")

        # nothing more happens on the next run
        self._run(self._context())
        self.save_and_sync.assert_called_once()

    def test_warn_window_without_recipient_untouched(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        self._remove_mails(user.eppn)
        self._enqueue(user.eppn)
        process_identity_age_users(self._context())
        self.save_and_sync.assert_not_called()
        assert self._identity(user.eppn, NIN).is_verified
        assert self._mails() == []
        assert self.identity_age_db._coll.count_documents({}) == 0
        self.stats.count.assert_any_call("identity_age_no_recipient_nin")

    def test_expired_gets_mail_between_runs_follows_warn_path(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(6))])
        original_mails = self._remove_mails(user.eppn)
        # first run with mail: warned, not unverified
        saved = self.amdb.get_user_by_eppn(user.eppn)
        saved.mail_addresses = original_mails
        self.amdb.save(saved)
        self._run(self._context())
        self.save_and_sync.assert_not_called()
        assert self._identity(user.eppn, NIN).is_verified
        assert set(self._payload_types()) == {"EduidIdentityExpiryWarningEmail"}
        assert self.identity_age_db.has_warning(user.eppn, NIN, _verified_at(user, NIN))

    def test_enqueue_failure_rolls_back_warning(self, mocker: MockerFixture) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        mocker.patch("eduid.workers.job_runner.helpers.enqueue_email", side_effect=RuntimeError("boom"))
        self._run(self._context())
        assert self._mails() == []
        assert not self.identity_age_db.has_warning(user.eppn, NIN, _verified_at(user, NIN))
        self.stats.count.assert_any_call("identity_age_failed")

    def test_partial_enqueue_failure_keeps_warning(self, mocker: MockerFixture) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        assert len(user.mail_addresses.verified) > 1
        from eduid.queue.client import enqueue_email

        calls = {"n": 0}

        def flaky(**kwargs: Any) -> QueueItem:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("boom")
            return enqueue_email(**kwargs)

        mocker.patch("eduid.workers.job_runner.helpers.enqueue_email", side_effect=flaky)
        self._run(self._context())
        queued = len(self._mails())
        assert 0 < queued < len(user.mail_addresses.verified)
        assert self.identity_age_db.has_warning(user.eppn, NIN, _verified_at(user, NIN))
        self._run(self._context())
        assert len(self._mails()) == queued

    def test_failed_sync_does_not_mark_unverified(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])
        assert user.identities.nin is not None
        self._set_warned(user, user.identities.nin, days_ago=31)
        self.save_and_sync.side_effect = None
        self.save_and_sync.return_value = False
        self._run(self._context())
        notification = self.identity_age_db.get(user.eppn, NIN, _verified_at(user, NIN))
        assert notification is not None
        assert notification.unverified_ts is None
        assert self._mails() == []
        self.stats.count.assert_any_call("identity_age_failed")

    def _expired_warned_user(self, identities: list[NinIdentity | EIDASIdentity]) -> User:
        user = self._save_user(identities)
        for identity in user.identities.verified:
            self._set_warned(user, identity, days_ago=40)
        return user

    def test_sync_not_applied_is_not_recorded_and_retries(self) -> None:
        """AM returns success but does not apply `identities` (e.g. old allowlist): nothing recorded or mailed."""
        user = self._expired_warned_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])
        self.save_and_sync.side_effect = None
        self.save_and_sync.return_value = True
        self._run(self._context())
        assert self._identity(user.eppn, NIN).is_verified
        notification = self.identity_age_db.get(user.eppn, NIN, _verified_at(user, NIN))
        assert notification is not None
        assert notification.unverified_ts is None
        assert self._mails() == []
        self.stats.count.assert_any_call("identity_age_sync_mismatch")
        self.stats.count.assert_any_call("identity_age_sync_mismatch_nin")
        counted = [c.args[0] for c in self.stats.count.call_args_list]
        assert "identity_age_unverified_nin" not in counted

        # AM is fixed: the next run lands, marks and mails
        self.save_and_sync.side_effect = lambda context, user, original=None: context.central_db.save(user)
        self._run(self._context())
        assert self._identity(user.eppn, NIN).is_verified is False
        notification = self.identity_age_db.get(user.eppn, NIN, _verified_at(user, NIN))
        assert notification is not None
        assert notification.unverified_ts is not None
        assert set(self._payload_types()) == {"EduidIdentityUnverifiedEmail"}
        self.stats.count.assert_any_call("identity_age_unverified_nin")

    def test_central_reread_failure_is_counted_and_not_recorded(self, mocker: MockerFixture) -> None:
        user = self._expired_warned_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])

        def save_then_break_reads(context: MockContext, user: User, original: User | None = None) -> bool:
            context.central_db.save(user)
            mocker.patch.object(self.amdb, "get_user_by_eppn", side_effect=RuntimeError("boom"))
            return True

        self.save_and_sync.side_effect = save_then_break_reads
        self._run(self._context())  # must not raise
        mocker.stopall()
        notification = self.identity_age_db.get(user.eppn, NIN, _verified_at(user, NIN))
        assert notification is not None
        assert notification.unverified_ts is None
        assert self._mails() == []
        self.stats.count.assert_any_call("identity_age_failed")
        counted = [c.args[0] for c in self.stats.count.call_args_list]
        assert "identity_age_unverified_nin" not in counted

    def test_partial_landing_only_records_landed_identity(self) -> None:
        user = self._expired_warned_user(
            [
                self._nin(verified_ts=_years_ago(5, extra_days=10)),
                self._eidas(created_ts=_years_ago(5, extra_days=10)),
            ]
        )
        eidas_verified_at = _verified_at(user, EIDAS)

        def only_nin_lands(context: MockContext, user: User, original: User | None = None) -> bool:
            applied = user.model_copy(deep=True)
            eidas = applied.identities.find(EIDAS.value)
            assert isinstance(eidas, IdentityElement)
            eidas.is_verified = True  # this change is dropped
            context.central_db.save(applied)
            return True

        self.save_and_sync.side_effect = only_nin_lands
        self._run(self._context())
        assert self._identity(user.eppn, NIN).is_verified is False
        assert self._identity(user.eppn, EIDAS).is_verified
        nin_notification = self.identity_age_db.get(user.eppn, NIN, _verified_at(user, NIN))
        eidas_notification = self.identity_age_db.get(user.eppn, EIDAS, eidas_verified_at)
        assert nin_notification is not None
        assert nin_notification.unverified_ts is not None
        assert eidas_notification is not None
        assert eidas_notification.unverified_ts is None
        assert {m["payload_type"] for m in self._mails()} == {"EduidIdentityUnverifiedEmail"}
        assert len(self._mails()) == len(user.mail_addresses.verified)
        assert all("identity_type" not in m["payload"] for m in self._mails())
        self.stats.count.assert_any_call("identity_age_unverified_nin")
        self.stats.count.assert_any_call("identity_age_sync_mismatch_eidas")
        counted = [c.args[0] for c in self.stats.count.call_args_list]
        assert "identity_age_unverified_eidas" not in counted
        assert "identity_age_sync_mismatch_nin" not in counted

    def test_mark_unverified_failure_does_not_skip_others(self, mocker: MockerFixture) -> None:
        user = self._save_user(
            [
                self._nin(verified_ts=_years_ago(5, extra_days=10)),
                self._eidas(created_ts=_years_ago(5, extra_days=10)),
            ]
        )
        for identity in user.identities.verified:
            self._set_warned(user, identity, days_ago=40)
        mocker.patch.object(IdentityAgeNotificationDB, "mark_unverified", side_effect=RuntimeError("boom"))
        self._run(self._context())
        assert self.amdb.get_user_by_eppn(user.eppn).identities.verified == []
        assert set(self._payload_types()) == {"EduidIdentityUnverifiedEmail"}
        assert len(self._payload_types()) == len(user.mail_addresses.verified)

    def test_reverified_same_verified_at_not_unverified_again(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])
        assert user.identities.nin is not None
        self._set_warned(user, user.identities.nin, days_ago=31)
        self._run(self._context())
        assert self._identity(user.eppn, NIN).is_verified is False
        self.save_and_sync.reset_mock()

        # verified again by something that did not touch verified_ts
        saved = self.amdb.get_user_by_eppn(user.eppn)
        assert saved.identities.nin is not None
        saved.identities.nin.is_verified = True
        self.amdb.save(saved)
        mails = len(self._mails())
        self._enqueue(user.eppn)
        process_identity_age_users(self._context())
        self.save_and_sync.assert_not_called()
        assert self._identity(user.eppn, NIN).is_verified
        assert len(self._mails()) == mails
        self.stats.count.assert_any_call("identity_age_unknown_nin")

    def test_unverify_rechecks_notice_period(self, mocker: MockerFixture) -> None:
        from eduid.workers.job_runner.jobs import identity_age as job

        user = self._save_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])
        assert user.identities.nin is not None
        self._set_warned(user, user.identities.nin, days_ago=31)
        context = self._context()
        limits = job._Limits(
            now=utc_now(),
            max_age=relativedelta(years=5),
            warning_period=relativedelta(months=3),
            min_notice=timedelta(days=30),
        )
        identity = user.identities.nin
        # warning record disappears (or was never sufficient) before the unverify step
        self.identity_age_db._coll.delete_many({})
        assert job._unverify_identities(context, user, [identity], limits) == 0
        self.save_and_sync.assert_not_called()
        # recent warning
        self._set_warned(user, user.identities.nin, days_ago=5)
        assert job._unverify_identities(context, user, [identity], limits) == 0
        self.save_and_sync.assert_not_called()

    def test_prefilter(self) -> None:
        self._save_user([self._nin(verified_ts=_years_ago(1))], eppn="hubba-young")
        self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))], eppn="hubba-old")
        self._save_user([self._nin(created_ts=_years_ago(4, extra_days=300))], eppn="hubba-oldc")
        self._save_user([self._nin(created_ts=_years_ago(1))], eppn="hubba-youngc")
        threshold = utc_now() - relativedelta(years=5) + relativedelta(months=3)
        docs = self.amdb.iter_unterminated_users_with_verified_identity(
            identity_types=list(IdentityType), projection={"eduPersonPrincipalName": 1}, verified_before=threshold
        )
        assert {d["eduPersonPrincipalName"] for d in docs} == {"hubba-old", "hubba-oldc"}
        docs = self.amdb.iter_unterminated_users_with_verified_identity(
            identity_types=list(IdentityType), projection={"eduPersonPrincipalName": 1}
        )
        assert len(list(docs)) == 4

    def _dry_run_logs(self, caplog: pytest.LogCaptureFixture) -> list[str]:
        return [r.getMessage() for r in caplog.records if r.getMessage().startswith("Dry run:")]

    def _assert_no_side_effects(self, user: User) -> None:
        assert self._mails() == []
        assert self.identity_age_db._coll.count_documents({}) == 0  # the real collection is never touched
        self.save_and_sync.assert_not_called()
        saved = self.amdb.get_user_by_eppn(user.eppn)
        assert saved.meta.version == user.meta.version
        assert all(i.is_verified for i in saved.identities.verified)

    def _counted(self, name: str) -> bool:
        return any(c.args == (name,) for c in self.stats.count.call_args_list)

    def test_gather_dry_run_queues_users(self) -> None:
        self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        gather_identity_age_users(self._context(dry_run=True))
        assert self._queue_size() == 1
        self.stats.count.assert_any_call("identity_age_queued")

    def test_dry_run_warn(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO)
        user = self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        self._run(process_context=self._context(dry_run=True))
        assert self._queue_size() == 0
        logs = self._dry_run_logs(caplog)
        assert len(logs) == 1
        assert f"would send expiry warning to {user.eppn} for identities [nin] expiring " in logs[0]
        assert "(2 verified addresses)" in logs[0]
        self.stats.count.assert_any_call("identity_age_dry_run_would_warn_nin")
        assert not self._counted("identity_age_warned_nin")
        self._assert_no_side_effects(user)
        assert self.dry_run_db._coll.count_documents({}) == 1
        assert self.dry_run_db.has_warning(user.eppn, NIN, _verified_at(user, NIN))

    def test_dry_run_expired_without_warning_is_warned_not_unverified(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO)
        user = self._save_user([self._nin(verified_ts=_years_ago(6))])
        self._run(process_context=self._context(dry_run=True))
        logs = self._dry_run_logs(caplog)
        assert len(logs) == 1
        assert "would send expiry warning" in logs[0]
        self.stats.count.assert_any_call("identity_age_dry_run_would_warn_nin")
        assert not self._counted("identity_age_dry_run_would_unverify_nin")
        self._assert_no_side_effects(user)

    def test_dry_run_unverify_after_notice(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO)
        user = self._save_user([self._nin(verified_ts=_years_ago(6))])
        assert user.identities.nin is not None
        self._set_warned(user, user.identities.nin, days_ago=60, db=self.dry_run_db)
        self._run(process_context=self._context(dry_run=True))
        logs = self._dry_run_logs(caplog)
        assert len(logs) == 2
        assert f"would unverify [nin] for {user.eppn} (notice sent nin=" in logs[0]
        assert "no recipient=False" in logs[0]
        assert f"would send unverified notice to {user.eppn} for identities [nin] (2 verified addresses)" in logs[1]
        self.stats.count.assert_any_call("identity_age_dry_run_would_unverify_nin")
        assert not self._counted("identity_age_unverified_nin")
        assert self._mails() == []
        self.save_and_sync.assert_not_called()
        assert self.identity_age_db._coll.count_documents({}) == 0
        record = self.dry_run_db.get(user.eppn, NIN, _verified_at(user, NIN))
        assert record is not None
        assert record.unverified_ts is not None
        assert self._identity(user.eppn, NIN).is_verified

    def test_dry_run_unverify_without_recipient(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO)
        user = self._save_user([self._nin(verified_ts=_years_ago(6))])
        self._remove_mails(user.eppn)
        user = self.amdb.get_user_by_eppn(user.eppn)
        self._run(process_context=self._context(dry_run=True))
        logs = self._dry_run_logs(caplog)
        assert len(logs) == 1
        assert f"would unverify [nin] for {user.eppn} (notice sent nin=none, no recipient=True)" in logs[0]
        self.stats.count.assert_any_call("identity_age_dry_run_would_unverify_nin")
        self._assert_no_side_effects(user)

    def test_dry_run_multiple_identities_one_line_per_action(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO)
        user = self._two_due_identities()
        self._run(process_context=self._context(dry_run=True))
        logs = self._dry_run_logs(caplog)
        assert len(logs) == 1
        assert "[nin, eidas]" in logs[0] or "[eidas, nin]" in logs[0]
        self.stats.count.assert_any_call("identity_age_dry_run_would_warn_nin")
        self.stats.count.assert_any_call("identity_age_dry_run_would_warn_eidas")
        self._assert_no_side_effects(user)

    def test_dry_run_unverify_multiple_identities_one_line(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO)
        user = self._save_user([self._nin(verified_ts=_years_ago(6)), self._eidas(created_ts=_years_ago(6))])
        assert user.identities.nin is not None
        assert user.identities.eidas is not None
        self._set_warned(user, user.identities.nin, days_ago=60, db=self.dry_run_db)
        self._set_warned(user, user.identities.eidas, days_ago=60, db=self.dry_run_db)
        self._run(process_context=self._context(dry_run=True))
        logs = self._dry_run_logs(caplog)
        assert len(logs) == 2
        assert "would unverify" in logs[0]
        assert "nin=" in logs[0]
        assert "eidas=" in logs[0]
        assert "would send unverified notice" in logs[1]
        self.stats.count.assert_any_call("identity_age_dry_run_would_unverify_nin")
        self.stats.count.assert_any_call("identity_age_dry_run_would_unverify_eidas")
        self.save_and_sync.assert_not_called()
        assert self._mails() == []

    def test_real_run_after_dry_run(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        self._run(process_context=self._context(dry_run=True))
        self._assert_no_side_effects(user)
        self._run(self._context())
        assert set(self._payload_types()) == {"EduidIdentityExpiryWarningEmail"}
        assert self.identity_age_db.has_warning(user.eppn, NIN, _verified_at(user, NIN))
        self.stats.count.assert_any_call("identity_age_warned_nin")

    def test_dry_run_full_flow(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO)
        user = self._save_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])
        verified_at = _verified_at(user, NIN)
        dry = self._context(dry_run=True)

        # Day 0: warn is recorded in the dry run collection only
        self._run(dry)
        assert self._dry_run_logs(caplog)[-1].startswith(f"Dry run: would send expiry warning to {user.eppn}")
        assert self.identity_age_db._coll.count_documents({}) == 0
        assert self.dry_run_db.has_warning(user.eppn, NIN, verified_at)

        # Within the notice period: nothing more to do, not even queued
        gather_identity_age_users(dry)
        assert self._queue_size() == 0

        # After min_notice_days: would unverify, recorded in the dry run collection
        self._set_warned(user, user.identities.nin, days_ago=31, db=self.dry_run_db)  # type: ignore[arg-type]
        caplog.clear()
        self._run(dry)
        logs = self._dry_run_logs(caplog)
        assert len(logs) == 2
        assert f"would unverify [nin] for {user.eppn}" in logs[0]
        self.stats.count.assert_any_call("identity_age_dry_run_would_unverify_nin")
        record = self.dry_run_db.get(user.eppn, NIN, verified_at)
        assert record is not None
        assert record.unverified_ts is not None

        # Third run: skipped quietly (not even queued)
        caplog.clear()
        self.stats.reset_mock()
        self._run(dry)
        assert self._dry_run_logs(caplog) == []
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert not self._counted("identity_age_dry_run_would_unverify_nin")

        self._assert_no_side_effects(user)

    def test_dry_run_already_simulated_skipped_quietly_when_queued(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO)
        user = self._save_user([self._nin(verified_ts=_years_ago(6))])
        self.dry_run_db.mark_unverified(user.eppn, NIN, _verified_at(user, NIN))
        self._enqueue(user.eppn)
        process_identity_age_users(self._context(dry_run=True))
        self.stats.count.assert_any_call("identity_age_dry_run_already_simulated_nin")
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert self._dry_run_logs(caplog) == []
        self._assert_no_side_effects(user)

    def test_real_run_ignores_dry_run_records(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(6))])
        verified_at = _verified_at(user, NIN)
        self._set_warned(user, user.identities.nin, days_ago=60, db=self.dry_run_db)  # type: ignore[arg-type]
        self.dry_run_db.mark_unverified(user.eppn, NIN, verified_at)
        self._run(self._context())
        # behaves as fresh: warns, does not unverify
        assert set(self._payload_types()) == {"EduidIdentityExpiryWarningEmail"}
        self.save_and_sync.assert_not_called()
        assert self._identity(user.eppn, NIN).is_verified
        assert self.identity_age_db.has_warning(user.eppn, NIN, verified_at)
        record = self.dry_run_db.get(user.eppn, NIN, verified_at)
        assert record is not None
        assert record.unverified_ts is not None

    def test_dry_run_ignores_real_records(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO)
        user = self._save_user([self._nin(verified_ts=_years_ago(6))])
        verified_at = _verified_at(user, NIN)
        self._set_warned(user, user.identities.nin, days_ago=60)  # type: ignore[arg-type]
        self.identity_age_db.mark_unverified(user.eppn, NIN, verified_at)
        real_before = self.identity_age_db.get(user.eppn, NIN, verified_at)
        self._run(self._context(dry_run=True))
        logs = self._dry_run_logs(caplog)
        assert len(logs) == 1
        assert "would send expiry warning" in logs[0]
        assert self.dry_run_db.has_warning(user.eppn, NIN, verified_at)
        assert self.identity_age_db.get(user.eppn, NIN, verified_at) == real_before
        assert self.identity_age_db._coll.count_documents({}) == 1
        assert self._mails() == []
        self.save_and_sync.assert_not_called()

    def test_gather_queues_only_users_needing_action(self) -> None:
        self._save_user([self._nin(verified_ts=_years_ago(1))], eppn="hubba-young")
        self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))], eppn="hubba-warn")
        self._save_user([self._nin(verified_ts=_years_ago(6))], eppn="hubba-expired")
        self._save_user([self._nin(verified_ts=_years_ago(6))], eppn="hubba-term", terminated=True)
        self._save_user([self._eidas(created_ts=_years_ago(6))], eppn="hubba-eidas")
        gather_identity_age_users(self._context(identity_types=[IdentityType.NIN]))
        for eppn, expected in [
            ("hubba-young", False),
            ("hubba-warn", True),
            ("hubba-expired", True),
            ("hubba-term", False),
            ("hubba-eidas", False),
        ]:
            assert self.cleaner_queue_db.user_in_queue(CleanerType.IDENTITY_AGE, eppn) is expected, eppn
        assert self._queue_size() == 2
        self.stats.count.assert_any_call("identity_age_queued")

    def test_gather_skips_warn_only_user_without_verified_mail(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        self._remove_mails(user.eppn)
        gather_identity_age_users(self._context())
        assert self._queue_size() == 0

    def test_gather_queues_expired_user_without_verified_mail(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(6))])
        self._remove_mails(user.eppn)
        gather_identity_age_users(self._context())
        assert self.cleaner_queue_db.user_in_queue(CleanerType.IDENTITY_AGE, user.eppn)

    def test_gather_queues_expired_recently_warned_user_who_lost_verified_mail(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])
        assert user.identities.nin is not None
        self._set_warned(user, user.identities.nin, days_ago=1)
        self._remove_mails(user.eppn)
        gather_identity_age_users(self._context())
        assert self.cleaner_queue_db.user_in_queue(CleanerType.IDENTITY_AGE, user.eppn)

    def test_gather_skips_expired_recently_warned_user_with_verified_mail(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])
        assert user.identities.nin is not None
        self._set_warned(user, user.identities.nin, days_ago=1)
        gather_identity_age_users(self._context())
        assert not self.cleaner_queue_db.user_in_queue(CleanerType.IDENTITY_AGE, user.eppn)

    def test_gather_queues_warn_user_with_verified_mail(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        assert user.mail_addresses.verified
        gather_identity_age_users(self._context())
        assert self.cleaner_queue_db.user_in_queue(CleanerType.IDENTITY_AGE, user.eppn)

    def test_unverified_notice_enqueue_failure_counted(self, mocker: MockerFixture) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])
        assert user.identities.nin is not None
        self._set_warned(user, user.identities.nin, days_ago=31)
        mocker.patch("eduid.workers.job_runner.helpers.enqueue_email", side_effect=RuntimeError("boom"))
        self._run(self._context())
        assert self._identity(user.eppn, NIN).is_verified is False
        assert self._mails() == []
        failed = [c for c in self.stats.count.call_args_list if c.args == ("identity_age_failed",)]
        assert len(failed) == 1

    def test_gather_is_idempotent(self) -> None:
        self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        context = self._context()
        gather_identity_age_users(context)
        gather_identity_age_users(context)
        assert self._queue_size() == 1

    def test_gather_queues_user_already_in_skv_queue(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        self.cleaner_queue_db.save(
            CleanerQueueUser(eppn=user.eppn, cleaner_type=CleanerType.SKV, identities=user.identities)
        )
        gather_identity_age_users(self._context())
        assert self.cleaner_queue_db.user_in_queue(CleanerType.IDENTITY_AGE, user.eppn)
        assert self.cleaner_queue_db.user_in_queue(CleanerType.SKV, user.eppn)
        self.stats.count.assert_any_call("identity_age_queued")

    def test_gather_save_failure_does_not_abort_sweep(self, mocker: MockerFixture) -> None:
        self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))], eppn="hubba-bad")
        self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))], eppn="hubba-good")
        original_save = self.cleaner_queue_db.save

        def flaky_save(user: CleanerQueueUser) -> UserSaveResult:
            if user.eppn == "hubba-bad":
                raise RuntimeError("boom")
            return original_save(user)

        mocker.patch.object(self.cleaner_queue_db, "save", side_effect=flaky_save)
        gather_identity_age_users(self._context())
        assert self.cleaner_queue_db.user_in_queue(CleanerType.IDENTITY_AGE, "hubba-good")
        assert not self.cleaner_queue_db.user_in_queue(CleanerType.IDENTITY_AGE, "hubba-bad")
        self.stats.count.assert_any_call("identity_age_gather_failed")
        self.stats.count.assert_any_call("identity_age_queued")

    def test_gather_skips_already_warned_user(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        assert user.identities.nin is not None
        self._set_warned(user, user.identities.nin, days_ago=1)
        gather_identity_age_users(self._context())
        assert self._queue_size() == 0

    def test_gather_queues_expired_user_after_notice_period(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(5, extra_days=10))])
        assert user.identities.nin is not None
        self._set_warned(user, user.identities.nin, days_ago=5)
        gather_identity_age_users(self._context())
        assert self._queue_size() == 0
        self._set_warned(user, user.identities.nin, days_ago=31)
        gather_identity_age_users(self._context())
        assert self._queue_size() == 1

    def test_process_one_user_per_call(self) -> None:
        for idx in range(3):
            self._save_user(
                [self._nin(verified_ts=_years_ago(4, extra_days=300), number=f"19900101123{idx}")],
                eppn=f"hubba-test{idx}",
            )
        context = self._context()
        gather_identity_age_users(context)
        assert self._queue_size() == 3
        for expected_queue, expected_warned in [(2, 1), (1, 2), (0, 3)]:
            process_identity_age_users(context)
            assert self._queue_size() == expected_queue
            assert self.identity_age_db._coll.count_documents({}) == expected_warned

    def test_process_empty_queue_is_noop(self) -> None:
        process_identity_age_users(self._context())
        assert self._mails() == []
        self.save_and_sync.assert_not_called()

    def test_process_failure_removes_user_from_queue(self, mocker: MockerFixture) -> None:
        self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        context = self._context()
        gather_identity_age_users(context)
        mocker.patch("eduid.workers.job_runner.jobs.identity_age._check_user", side_effect=RuntimeError("boom"))
        process_identity_age_users(context)
        assert self._queue_size() == 0
        self.stats.count.assert_any_call("identity_age_failed")

    def test_process_user_terminated_after_queueing(self) -> None:
        user = self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))])
        context = self._context()
        gather_identity_age_users(context)
        saved = self.amdb.get_user_by_eppn(user.eppn)
        saved.terminated = utc_now()
        self.amdb.save(saved)
        process_identity_age_users(context)
        assert self._queue_size() == 0
        assert self._mails() == []

    def test_terminated_user_skipped(self) -> None:
        self._save_user([self._nin(verified_ts=_years_ago(4, extra_days=300))], terminated=True)
        self._run(self._context())
        assert self._mails() == []

    def test_unknown_is_never_unverified(self) -> None:
        nin = self._nin()
        nin.no_created_ts_in_db = True
        nin.verified_ts = None
        user = self._save_user([nin])
        self._enqueue(user.eppn)
        process_identity_age_users(self._context())
        assert self._mails() == []
        self.save_and_sync.assert_not_called()
        assert self._identity(user.eppn, NIN).is_verified
        self.stats.count.assert_any_call("identity_age_unknown_nin")

    def test_multiple_identities_one_save(self) -> None:
        user = self._save_user(
            [
                self._nin(verified_ts=_years_ago(5, extra_days=10)),
                self._eidas(created_ts=_years_ago(5, extra_days=10)),
            ]
        )
        for identity in user.identities.verified:
            assert hasattr(identity, "verified_at")
            self._set_warned(user, identity, days_ago=40)
        self._run(self._context())
        self.save_and_sync.assert_called_once()
        assert self._identity(user.eppn, NIN).is_verified is False
        assert self._identity(user.eppn, EIDAS).is_verified is False

    def _two_due_identities(self, nin_extra_days: int = 300, eidas_extra_days: int = 300) -> User:
        return self._save_user(
            [
                self._nin(verified_ts=_years_ago(4, extra_days=nin_extra_days)),
                self._eidas(created_ts=_years_ago(4, extra_days=eidas_extra_days)),
            ]
        )

    def test_two_warnings_one_mail_per_address(self) -> None:
        user = self._two_due_identities()
        addresses = {a.email for a in user.mail_addresses.verified}
        assert len(addresses) == 2
        context = self._context()
        self._run(context)
        mails = self._mails()
        assert len(mails) == 2
        assert {m["payload_type"] for m in mails} == {"EduidIdentityExpiryWarningEmail"}
        assert {m["payload"]["email"] for m in mails} == addresses
        assert self.identity_age_db.has_warning(user.eppn, NIN, _verified_at(user, NIN))
        assert self.identity_age_db.has_warning(user.eppn, EIDAS, _verified_at(user, EIDAS))
        self.stats.count.assert_any_call("identity_age_warned_nin")
        self.stats.count.assert_any_call("identity_age_warned_eidas")

        self._run(context)
        assert len(self._mails()) == 2

    def test_warning_uses_earliest_expiry(self) -> None:
        from eduid.workers.job_runner.jobs import identity_age as job

        user = self._two_due_identities(nin_extra_days=300, eidas_extra_days=330)
        context = self._context()
        limits = job._limits(context)
        nin = user.identities.nin
        eidas = user.identities.eidas
        assert nin is not None
        assert eidas is not None
        dates = [job._notice_date(nin, limits), job._notice_date(eidas, limits)]
        assert dates[0] != dates[1]
        self._run(context)
        mails = self._mails()
        assert len(mails) == 2
        assert {m["payload"]["expires_at"] for m in mails} == {min(dates)}

    def test_warning_only_covers_identities_needing_it(self) -> None:
        user = self._two_due_identities()
        assert user.identities.eidas is not None
        self._set_warned(user, user.identities.eidas, days_ago=1)
        self._run(self._context())
        assert len(self._mails()) == 2
        assert self.identity_age_db.has_warning(user.eppn, NIN, _verified_at(user, NIN))

    def test_enqueue_failure_rolls_back_all_warning_records(self, mocker: MockerFixture) -> None:
        user = self._two_due_identities()
        mocker.patch("eduid.workers.job_runner.helpers.enqueue_email", side_effect=RuntimeError("boom"))
        self._run(self._context())
        assert self._mails() == []
        assert not self.identity_age_db.has_warning(user.eppn, NIN, _verified_at(user, NIN))
        assert not self.identity_age_db.has_warning(user.eppn, EIDAS, _verified_at(user, EIDAS))
        self.stats.count.assert_any_call("identity_age_failed")
        counted = [c.args[0] for c in self.stats.count.call_args_list]
        assert "identity_age_warned_nin" not in counted

    def test_no_recipient_counted_per_identity(self) -> None:
        user = self._two_due_identities()
        self._remove_mails(user.eppn)
        self._enqueue(user.eppn)
        process_identity_age_users(self._context())
        assert self._mails() == []
        self.stats.count.assert_any_call("identity_age_no_recipient_nin")
        self.stats.count.assert_any_call("identity_age_no_recipient_eidas")

    def test_two_unverified_one_notice_per_address(self) -> None:
        user = self._expired_warned_user(
            [
                self._nin(verified_ts=_years_ago(5, extra_days=10)),
                self._eidas(created_ts=_years_ago(5, extra_days=10)),
            ]
        )
        assert len(user.mail_addresses.verified) == 2
        self._run(self._context())
        mails = self._mails()
        assert len(mails) == 2
        assert {m["payload_type"] for m in mails} == {"EduidIdentityUnverifiedEmail"}
        for identity_type in (NIN, EIDAS):
            notification = self.identity_age_db.get(user.eppn, identity_type, _verified_at(user, identity_type))
            assert notification is not None
            assert notification.unverified_ts is not None
        self.stats.count.assert_any_call("identity_age_unverified_nin")
        self.stats.count.assert_any_call("identity_age_unverified_eidas")

    def test_identity_type_filter(self) -> None:
        user = self._save_user(
            [
                self._nin(verified_ts=_years_ago(4, extra_days=300)),
                self._eidas(created_ts=_years_ago(4, extra_days=300)),
            ]
        )
        self._run(self._context(identity_types=[IdentityType.EIDAS]))
        assert {m["payload_type"] for m in self._mails()} == {"EduidIdentityExpiryWarningEmail"}
        assert user.identities.eidas is not None
        self.stats.count.assert_any_call("identity_age_warned_eidas")
        assert user.identities.nin is not None
        assert not self.identity_age_db.has_warning(user.eppn, NIN, _verified_at(user, NIN))


class TestSchedulerAndConfig:
    def test_scheduler_accepts_job_name(self, mocker: MockerFixture) -> None:
        from eduid.workers.job_runner.config import JobCronConfig
        from eduid.workers.job_runner.scheduler import JobScheduler

        context = mocker.MagicMock()
        context.config.environment = "dev"
        context.worker_name = "test_worker"
        context.config.jobs = {
            "dev": {
                "gather_identity_age_users": JobCronConfig(hour=3),
                "process_identity_age_users": JobCronConfig(minute="*/5"),
            }
        }
        scheduler = JobScheduler()
        add_job = mocker.patch.object(scheduler, "add_job")
        scheduler.schedule_jobs(context)
        assert [c.args[0] for c in add_job.call_args_list] == [gather_identity_age_users, process_identity_age_users]

    def test_config_defaults(self) -> None:
        config = IdentityAgeConfig()
        assert config.max_age_years == 5
        assert config.warning_period_months == 3
        assert config.min_notice_days == 30
        assert set(config.identity_types) == set(IdentityType)

    @pytest.mark.parametrize(
        "identity_age",
        [
            {"max_age_years": 0},
            {"max_age_years": -1},
            {"warning_period_months": -1},
            {"min_notice_days": 0},
            {"mail_expires_in_days": 0},
            {"notification_auto_expire": 0},
            {"notification_auto_expire": -86400},
            {"notification_auto_expire": "garbage"},
            # default warning_period_months=3, min_notice_days=30: lifetime 3 * 31 + 30 = 123 days
            {"notification_auto_expire": timedelta(days=123)},
            {"notification_auto_expire": "P123D"},
            {"notification_auto_expire": timedelta(days=100), "warning_period_months": 6, "min_notice_days": 1},
            {"max_age_years": 1, "warning_period_months": 12},
            {"max_age_years": 1, "warning_period_months": 24},
            {"max_age_years": 5, "warning_period_months": 60},
        ],
    )
    def test_config_rejects_invalid_values(self, identity_age: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            IdentityAgeConfig(**identity_age)

    def test_config_auto_expire_default(self) -> None:
        assert IdentityAgeConfig().notification_auto_expire == timedelta(days=3 * 365)

    def test_config_accepts_boundary_values(self) -> None:
        config = IdentityAgeConfig(
            max_age_years=1,
            warning_period_months=0,
            min_notice_days=1,
            mail_expires_in_days=1,
            notification_auto_expire=timedelta(days=2),
        )
        assert config.min_notice_days == 1
        assert IdentityAgeConfig(max_age_years=1, warning_period_months=11).warning_period_months == 11

    def test_config_auto_expire_must_exceed_record_lifetime(self) -> None:
        with pytest.raises(ValidationError, match="notification_auto_expire"):
            IdentityAgeConfig(notification_auto_expire=timedelta(days=123))
        assert IdentityAgeConfig(notification_auto_expire=timedelta(days=124)).notification_auto_expire == timedelta(
            days=124
        )
        config = IdentityAgeConfig(
            warning_period_months=6, min_notice_days=14, notification_auto_expire=timedelta(days=201)
        )
        assert config.notification_auto_expire == timedelta(days=201)
        with pytest.raises(ValidationError, match="notification_auto_expire"):
            IdentityAgeConfig(warning_period_months=6, min_notice_days=14, notification_auto_expire=timedelta(days=200))

    def test_config_auto_expire_parses_durations(self) -> None:
        assert IdentityAgeConfig(notification_auto_expire="P200D").notification_auto_expire == timedelta(days=200)
        assert IdentityAgeConfig(notification_auto_expire=200 * 86400).notification_auto_expire == timedelta(days=200)
        assert IdentityAgeConfig.model_validate(
            {"notification_auto_expire": "P30D", "min_notice_days": 1, "warning_period_months": 0}
        ).notification_auto_expire == timedelta(days=30)
