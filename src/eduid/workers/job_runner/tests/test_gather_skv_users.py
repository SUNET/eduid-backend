import logging
from collections.abc import Iterator
from datetime import datetime

import pytest

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.identity import IdentityList, NinIdentity
from eduid.userdb.meta import CleanerType
from eduid.userdb.user import User
from eduid.userdb.user_cleaner.db import CleanerQueueUser
from eduid.userdb.userdb import AmDB
from eduid.workers.job_runner.jobs.skv import gather_skv_users
from eduid.workers.job_runner.testing import CleanerQueueTestCase, MockContext


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
