import logging
from collections.abc import Iterator
from datetime import datetime

import pytest
from pytest_mock import MockerFixture

from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.msg_relay import NavetData
from eduid.common.stats import AppStats
from eduid.userdb.exceptions import UserDoesNotExist
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.identity import EIDASIdentity, IdentityList, NinIdentity
from eduid.userdb.meta import CleanerType
from eduid.userdb.user import User
from eduid.userdb.user_cleaner.db import CleanerQueueUser
from eduid.userdb.user_cleaner.userdb import CleanerUserDB
from eduid.userdb.userdb import AmDB, UserSaveResult
from eduid.workers.job_runner.jobs.skv import check_user_official_name, gather_skv_users, terminate_user
from eduid.workers.job_runner.testing import CleanerQueueTestCase, MockContext
from eduid.workers.msg.tasks import MessageSender


class TestGatherSkvUsers(CleanerQueueTestCase):
    """Tests for the gather_skv_users function."""

    users = UserFixtures()

    @pytest.fixture(autouse=True)
    def setup(self, setup_cleaner: None) -> Iterator[None]:
        self.amdb = AmDB(db_uri=self.mongo_uri)
        self.amdb._drop_whole_collection()  # clean any leftovers from other tests on this worker
        self.context = MockContext(
            central_db=self.amdb,
            cleaner_queue=self.cleaner_queue_db,
            logger=logging.getLogger("test_gather_skv_users"),
        )

        yield

        self.amdb._drop_whole_collection()

    def _create_user_with_verified_nin(self, eppn: str, nin_number: str) -> User:
        """Create and return a User with a verified NIN identity."""
        nin = NinIdentity(
            number=nin_number,
            created_ts=datetime.fromisoformat("2022-09-02T10:23:25"),
            created_by="test",
            is_verified=True,
            verified_by="test",
            verified_ts=datetime.fromisoformat("2022-09-02T10:23:25"),
        )
        return User(
            eppn=eppn,
            identities=IdentityList(elements=[nin]),
            credentials=self.users.mocked_user_standard.credentials,
        )

    def test_queues_user_with_verified_nin(self) -> None:
        """A user with a verified NIN should be added to the cleaner queue."""
        user = self._create_user_with_verified_nin(eppn="hubba-test1", nin_number="199001011234")
        self.amdb.save(user)

        gather_skv_users(self.context)

        assert self.cleaner_queue_db.user_in_queue(cleaner_type=CleanerType.SKV, eppn="hubba-test1")

    def test_queues_multiple_users(self) -> None:
        """Multiple users with verified NINs should all be queued."""
        user1 = self._create_user_with_verified_nin(eppn="hubba-test1", nin_number="199001011234")
        user2 = self._create_user_with_verified_nin(eppn="hubba-test2", nin_number="199002021234")
        self.amdb.save(user1)
        self.amdb.save(user2)

        gather_skv_users(self.context)

        assert self.cleaner_queue_db.user_in_queue(cleaner_type=CleanerType.SKV, eppn="hubba-test1")
        assert self.cleaner_queue_db.user_in_queue(cleaner_type=CleanerType.SKV, eppn="hubba-test2")

    def test_queues_user_already_in_identity_age_queue(self) -> None:
        """A user queued for IDENTITY_AGE must still be queued for SKV."""
        user = self._create_user_with_verified_nin(eppn="hubba-test1", nin_number="199001011234")
        self.amdb.save(user)
        self.cleaner_queue_db.save(
            CleanerQueueUser(eppn="hubba-test1", cleaner_type=CleanerType.IDENTITY_AGE, identities=user.identities)
        )

        gather_skv_users(self.context)

        assert self.cleaner_queue_db.user_in_queue(cleaner_type=CleanerType.SKV, eppn="hubba-test1")
        assert self.cleaner_queue_db.user_in_queue(cleaner_type=CleanerType.IDENTITY_AGE, eppn="hubba-test1")

    def test_save_failure_does_not_abort_sweep(self, mocker: MockerFixture) -> None:
        """A failure to queue one user must not stop the sweep."""
        self.amdb.save(self._create_user_with_verified_nin(eppn="hubba-bad", nin_number="199001011234"))
        self.amdb.save(self._create_user_with_verified_nin(eppn="hubba-good", nin_number="199002021234"))
        original_save = self.cleaner_queue_db.save

        def flaky_save(user: CleanerQueueUser) -> UserSaveResult:
            if user.eppn == "hubba-bad":
                raise RuntimeError("boom")
            return original_save(user)

        mocker.patch.object(self.cleaner_queue_db, "save", side_effect=flaky_save)
        stats = mocker.MagicMock(spec=AppStats)
        self.context.stats = stats

        gather_skv_users(self.context)

        assert self.cleaner_queue_db.user_in_queue(cleaner_type=CleanerType.SKV, eppn="hubba-good")
        assert not self.cleaner_queue_db.user_in_queue(cleaner_type=CleanerType.SKV, eppn="hubba-bad")
        stats.count.assert_called_once_with("skv_gather_failed")

    def test_skips_user_already_in_queue(self) -> None:
        """A user already in the cleaner queue should not be added again."""
        user = self._create_user_with_verified_nin(eppn="hubba-test1", nin_number="199001011234")
        self.amdb.save(user)

        # Pre-populate the queue
        queue_user = CleanerQueueUser(eppn="hubba-test1", cleaner_type=CleanerType.SKV, identities=user.identities)
        self.cleaner_queue_db.save(queue_user)

        # Run gather - should skip the user already in queue
        gather_skv_users(self.context)

        # Verify user is still in queue (exactly once - drain and count)
        first = self.cleaner_queue_db.get_next_user(CleanerType.SKV)
        second = self.cleaner_queue_db.get_next_user(CleanerType.SKV)
        assert first is not None
        assert first.eppn == "hubba-test1"
        assert second is None

    def test_skips_user_without_verified_nin(self) -> None:
        """A user without a verified NIN should not be queued."""
        user = self.users.mocked_user_standard_2  # has empty IdentityList
        self.amdb.save(user)

        gather_skv_users(self.context)

        assert not self.cleaner_queue_db.user_in_queue(cleaner_type=CleanerType.SKV, eppn=user.eppn)

    def test_skips_terminated_user(self) -> None:
        """A terminated user with a verified NIN should not be queued."""
        user = self._create_user_with_verified_nin(eppn="hubba-test1", nin_number="199001011234")
        self.amdb.save(user)

        # Terminate the user directly in MongoDB
        loaded = self.amdb.get_user_by_eppn("hubba-test1")
        loaded.terminated = utc_now()
        self.amdb.save(loaded)

        gather_skv_users(self.context)

        assert not self.cleaner_queue_db.user_in_queue(cleaner_type=CleanerType.SKV, eppn="hubba-test1")

    def test_queued_user_has_correct_identities(self) -> None:
        """The queued CleanerQueueUser should have the correct NIN identity."""
        user = self._create_user_with_verified_nin(eppn="hubba-test1", nin_number="199001011234")
        self.amdb.save(user)

        gather_skv_users(self.context)

        queued = self.cleaner_queue_db.get_next_user(CleanerType.SKV)
        assert queued is not None
        assert queued.eppn == "hubba-test1"
        assert queued.identities.nin is not None
        assert queued.identities.nin.number == "199001011234"

    def test_empty_database(self) -> None:
        """gather_skv_users should handle an empty database without errors."""
        gather_skv_users(self.context)

        # Nothing should be in the queue
        assert self.cleaner_queue_db.get_next_user(CleanerType.SKV) is None


class TestSkvConcurrentCentralChange(CleanerQueueTestCase):
    """A central identities change between load and sync must not be overwritten by skv jobs."""

    users = UserFixtures()

    @pytest.fixture(autouse=True)
    def setup(self, setup_cleaner: None, mocker: MockerFixture) -> Iterator[None]:
        self.amdb = AmDB(db_uri=self.mongo_uri)
        self.amdb._drop_whole_collection()
        self.private_db = CleanerUserDB(db_uri=self.mongo_uri)
        self.private_db._drop_whole_collection()
        self.am_relay = mocker.MagicMock()
        self.proofing_log = mocker.MagicMock()
        self.proofing_log.save.return_value = True
        self.context = MockContext(
            central_db=self.amdb,
            cleaner_queue=self.cleaner_queue_db,
            logger=logging.getLogger("test_skv_concurrent"),
        )
        self.context.private_db = self.private_db
        self.context.am_relay = self.am_relay
        self.context.proofing_log = self.proofing_log
        self.stats = mocker.MagicMock()
        self.context.stats = self.stats

        user = User(
            eppn="hubba-test1",
            identities=IdentityList(
                elements=[
                    NinIdentity(
                        number="199001011234",
                        created_ts=datetime.fromisoformat("2022-09-02T10:23:25"),
                        created_by="test",
                        is_verified=True,
                        verified_by="test",
                        verified_ts=datetime.fromisoformat("2022-09-02T10:23:25"),
                    )
                ]
            ),
            credentials=self.users.mocked_user_standard.credentials,
        )
        user.given_name = "Old"
        user.surname = "Name"
        self.amdb.save(user)
        self.queue_user = CleanerQueueUser(eppn="hubba-test1", cleaner_type=CleanerType.SKV, identities=user.identities)

        # a webapp verifies an eIDAS identity after the job loaded the user
        original_get = self.amdb.get_user_by_eppn
        self.racing = True

        def racing_get(eppn: str) -> User:
            loaded = original_get(eppn)
            if self.racing:
                self.racing = False  # only change once, the first load is the job's
                central = original_get(eppn)
                central.identities.add(
                    EIDASIdentity(
                        prid="XX/YY/1234",
                        prid_persistence="A",
                        loa="eidas-nf-high",
                        country_code="XX",
                        created_by="test",
                        is_verified=True,
                        verified_by="test",
                        verified_ts=utc_now(),
                        date_of_birth=datetime.fromisoformat("1990-01-01T00:00:00"),
                    )
                )
                self.amdb.save(central)
            return loaded

        mocker.patch.object(self.amdb, "get_user_by_eppn", side_effect=racing_get)
        yield
        self.amdb._drop_whole_collection()
        self.private_db._drop_whole_collection()

    def _assert_not_overwritten(self) -> None:
        self.am_relay.request_user_sync.assert_not_called()
        assert self.private_db._coll.count_documents({}) == 0
        central = self.amdb.get_user_by_eppn("hubba-test1")
        assert central.identities.find("eidas") is not None
        assert central.terminated is None

    def test_terminate_user_does_not_overwrite_concurrent_change(self) -> None:
        assert terminate_user(self.context, self.queue_user) is False
        self._assert_not_overwritten()

    def test_official_name_update_does_not_overwrite_concurrent_change(self) -> None:
        navet_data = NavetData(**MessageSender.get_devel_all_navet_data(identity_number="199001011234"))
        check_user_official_name(self.context, self.queue_user, navet_data)
        self._assert_not_overwritten()
        assert self.amdb.get_user_by_eppn("hubba-test1").given_name == "Old"

    def test_terminate_user_without_concurrent_change(self) -> None:
        self.racing = False
        assert terminate_user(self.context, self.queue_user) is True
        self.am_relay.request_user_sync.assert_called_once()

    def _delete_user_after_load(self, mocker: MockerFixture) -> None:
        """The job loads the user, then the user is gone when the stale guard re-reads it."""
        self.racing = False
        loaded = self.amdb.get_user_by_eppn("hubba-test1")
        mocker.patch.object(self.amdb, "get_user_by_eppn", side_effect=[loaded, UserDoesNotExist("gone")])

    def test_terminate_user_deleted_after_load(self, mocker: MockerFixture) -> None:
        self._delete_user_after_load(mocker)
        assert terminate_user(self.context, self.queue_user) is False
        self.am_relay.request_user_sync.assert_not_called()
        self.stats.count.assert_called_with(name="skv_user_gone")

    def test_official_name_update_deleted_after_load(self, mocker: MockerFixture) -> None:
        self._delete_user_after_load(mocker)
        navet_data = NavetData(**MessageSender.get_devel_all_navet_data(identity_number="199001011234"))
        check_user_official_name(self.context, self.queue_user, navet_data)
        self.am_relay.request_user_sync.assert_not_called()
        self.stats.count.assert_called_with(name="skv_user_gone")
