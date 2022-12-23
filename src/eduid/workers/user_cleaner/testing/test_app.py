from typing import Any
from eduid.common.testing_base import CommonTestCase
from eduid.userdb.fixtures.users import new_user_example, new_user_example2, new_unverified_user_example
from eduid.workers.user_cleaner.app import init_worker_base
from eduid.userdb.identity import IdentityType
from eduid.userdb.meta import CleanerType


class AppTest(CommonTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(am_users=[new_user_example, new_user_example2, new_unverified_user_example])

        self.app = init_worker_base(
            cleaner_type=CleanerType.SKV, identity_type=IdentityType.NIN, test_config=self._get_config()
        )

    def _get_config(self) -> dict[str, Any]:
        return {
            "app_name": "test",
            "mongo_uri": self.settings["mongo_uri"],
            "minimum_delay": 1000,
            "time_to_clean_dataset": 2592000000,
            "debug": True,
            "change_quota": 2,
            "amapi": {
                "url": "",
                "tls_verify": False,
            },
            "celery": {},
            "gnap_auth_data": {
                "auth_server_url": "",
                "auth_server_verify": True,
                "key_name": "",
                "client_jwk": {},
                "access": [""],  # List[Union[str, Access]] = Field(default_factory=list)
            },
        }

    def test_populate_queue(self):
        users = [new_user_example, new_user_example2, new_unverified_user_example]
        self.app._populate_queue(users=users)
        got_user1 = self.app.queue.get()
        assert got_user1["eppn"] == new_user_example.eppn
        assert got_user1["nin"] == new_user_example.identities.nin.number

        got_user2 = self.app.queue.get()
        assert got_user2["eppn"] == new_user_example2.eppn
        assert got_user2["nin"] == new_user_example2.identities.nin.number

    def test_get_delay_time(self):
        got = self.app.get_delay_time()
        assert got == 1294705
