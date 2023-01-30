from typing import Any
from eduid.common.testing_base import CommonTestCase
from eduid.userdb.fixtures.users import UserFixtures
from eduid.workers.user_cleaner.app import init_worker_base
from eduid.userdb.identity import IdentityType
from eduid.userdb.meta import CleanerType


class AppTest(CommonTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(
            am_users=[
                UserFixtures().new_user_example,
                UserFixtures().new_unverified_user_example,
            ]
        )

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
