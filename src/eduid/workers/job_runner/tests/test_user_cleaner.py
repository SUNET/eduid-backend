import pytest
from pymongo.errors import DuplicateKeyError

from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.meta import CleanerType
from eduid.userdb.user_cleaner.db import CleanerQueueDB, CleanerQueueUser
from eduid.workers.job_runner.testing import CleanerQueueTestCase


class TestCleanerQueueDB(CleanerQueueTestCase):
    users = UserFixtures()

    def test_queue_order(self) -> None:
        first = self.users.mocked_user_standard
        second = self.users.mocked_user_standard_2
        first_user: CleanerQueueUser = CleanerQueueUser(
            eppn=first.eppn, cleaner_type=CleanerType.SKV, identities=first.identities
        )
        self.cleaner_queue_db.save(first_user)
        second_user: CleanerQueueUser = CleanerQueueUser(
            eppn=second.eppn, cleaner_type=CleanerType.SKV, identities=second.identities
        )
        self.cleaner_queue_db.save(second_user)

        first_user_from_db = self.cleaner_queue_db.get_next_user(CleanerType.SKV)
        second_user_from_db = self.cleaner_queue_db.get_next_user(CleanerType.SKV)

        assert first_user_from_db
        assert first_user_from_db.eppn == first.eppn
        assert second_user_from_db
        assert second_user_from_db.eppn == second_user.eppn

    def test_mixed_queue(self) -> None:
        first = self.users.mocked_user_standard
        second = self.users.mocked_user_standard_2
        ladok_queue_user: CleanerQueueUser = CleanerQueueUser(
            eppn=first.eppn, cleaner_type=CleanerType.LADOK, identities=first.identities
        )
        self.cleaner_queue_db.save(ladok_queue_user)
        skv_queue_user: CleanerQueueUser = CleanerQueueUser(
            eppn=second.eppn, cleaner_type=CleanerType.SKV, identities=second.identities
        )
        self.cleaner_queue_db.save(skv_queue_user)

        first_user_from_db = self.cleaner_queue_db.get_next_user(CleanerType.SKV)
        second_user_from_db = self.cleaner_queue_db.get_next_user(CleanerType.SKV)
        third_user_from_db = self.cleaner_queue_db.get_next_user(CleanerType.LADOK)

        assert first_user_from_db
        assert first_user_from_db.eppn == skv_queue_user.eppn
        assert second_user_from_db is None
        assert third_user_from_db
        assert third_user_from_db.eppn == ladok_queue_user.eppn

    def test_same_eppn_in_two_cleaner_types(self) -> None:
        user = self.users.mocked_user_standard
        for cleaner_type in (CleanerType.SKV, CleanerType.IDENTITY_AGE):
            self.cleaner_queue_db.save(
                CleanerQueueUser(eppn=user.eppn, cleaner_type=cleaner_type, identities=user.identities)
            )
        assert self.cleaner_queue_db.user_in_queue(CleanerType.SKV, user.eppn)
        assert self.cleaner_queue_db.user_in_queue(CleanerType.IDENTITY_AGE, user.eppn)

        skv = self.cleaner_queue_db.get_next_user(CleanerType.SKV)
        assert skv is not None
        assert skv.eppn == user.eppn
        assert skv.cleaner_type == CleanerType.SKV
        # removing the SKV entry leaves the IDENTITY_AGE one
        assert not self.cleaner_queue_db.user_in_queue(CleanerType.SKV, user.eppn)
        assert self.cleaner_queue_db.user_in_queue(CleanerType.IDENTITY_AGE, user.eppn)
        assert self.cleaner_queue_db.get_next_user(CleanerType.SKV) is None

        age = self.cleaner_queue_db.get_next_user(CleanerType.IDENTITY_AGE)
        assert age is not None
        assert age.eppn == user.eppn
        assert age.cleaner_type == CleanerType.IDENTITY_AGE
        assert self.cleaner_queue_db.get_next_user(CleanerType.IDENTITY_AGE) is None

    def test_same_eppn_same_cleaner_type_rejected(self) -> None:
        user = self.users.mocked_user_standard
        self.cleaner_queue_db.save(
            CleanerQueueUser(eppn=user.eppn, cleaner_type=CleanerType.SKV, identities=user.identities)
        )
        with pytest.raises(DuplicateKeyError):
            self.cleaner_queue_db.save(
                CleanerQueueUser(eppn=user.eppn, cleaner_type=CleanerType.SKV, identities=user.identities)
            )

    def test_old_eppn_only_unique_index_is_migrated(self) -> None:
        coll = self.cleaner_queue_db._coll
        coll.drop_index("eppn-cleaner-type-index-v1")
        coll.create_index([("eduPersonPrincipalName", 1)], name="eppn-index-v1", unique=True)
        assert "eppn-index-v1" in coll.index_information()

        # A new instance runs setup_indexes, as on job runner startup
        db = CleanerQueueDB(db_uri=self.mongo_uri)

        info = db._coll.index_information()
        assert "eppn-index-v1" not in info
        assert not [name for name, v in info.items() if v.get("unique") and v["key"] == [("eduPersonPrincipalName", 1)]]
        assert info["eppn-cleaner-type-index-v1"]["unique"]
        assert info["eppn-cleaner-type-index-v1"]["key"] == [("eduPersonPrincipalName", 1), ("cleaner_type", 1)]
