from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.meta import CleanerType
from eduid.userdb.user_cleaner.db import CleanerQueueUser
from eduid.workers.job_runner.testing import CleanerQueueTestCase


class TestCleanerQueueDB(CleanerQueueTestCase):
    users = UserFixtures()

    def setUp(self):
        super().setUp()

    def test_queue_order(self):
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

        self.assertEqual(first_user_from_db.eppn, first.eppn)
        self.assertEqual(second_user_from_db.eppn, second_user.eppn)

    def test_mixed_queue(self):
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

        self.assertEqual(first_user_from_db.eppn, skv_queue_user.eppn)
        self.assertIsNone(second_user_from_db)
        self.assertEqual(third_user_from_db.eppn, ladok_queue_user.eppn)
