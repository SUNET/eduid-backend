from typing import Any, Dict
from eduid.common.testing_base import CommonTestCase
from eduid.userdb.fixtures.users import new_user_example, new_user_example2, new_unverified_user_example
from eduid.workers.user_cleaner.workers.skv import init_skv_worker
from eduid.userdb.identity import IdentityType
from eduid.userdb.meta import CleanerType
from eduid.common.rpc.msg_relay import Name, NavetData, OfficialAddress, Person, PostalAddresses


class WorkerTest(CommonTestCase):
    def setUp(self, *args, **kwargs):
        super().setUp(am_users=[new_user_example, new_user_example2, new_unverified_user_example])

        self.skv = init_skv_worker(test_config=self._get_config())

    def _get_config(self) -> Dict[str, Any]:
        return {
            "app_name": "test",
            "mongo_uri": self.settings["mongo_uri"],
            "minimum_delay": 1,
            "time_to_clean_dataset": 30,
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

    def test_update_name(self):
        queue_user = {
            "eppn": new_user_example.eppn,
            "nin": new_user_example.identities.nin.number,
        }
        navet_data = NavetData(
            person=Person(
                name=Name(
                    # given_name_marking: Optional[str] = Field(default=None, alias="GivenNameMarking")
                    given_name="test_given_name",
                    # middle_name="test_middle_name": Optional[str] = Field(default=None, alias="MiddleName")
                    surname="test_surname",
                ),
            ),
        )
        self.skv.update_name(queue_user=queue_user, navet_data=navet_data)

        got = self.skv.db.get_user_by_eppn(new_user_example.eppn)

        assert got.given_name == "test_given_name"
        assert got.surname == "test_surname"
