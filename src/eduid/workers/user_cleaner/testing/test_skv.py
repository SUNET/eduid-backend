from typing import Any, Dict
from unittest.mock import MagicMock, patch
from eduid.common.clients.amapi_client.testing import MockedAMAPIMixin
from eduid.common.testing_base import CommonTestCase
from eduid.userdb.fixtures.users import UserFixtures
from eduid.workers.user_cleaner.workers.skv import init_skv_worker
from eduid.common.rpc.msg_relay import (
    NavetData,
)
import pytest
from jwcrypto.jwk import JWK

from eduid.workers.msg.tasks import MessageSender
from eduid.userdb.user_cleaner.cache import CacheUser


class WorkerTest(CommonTestCase, MockedAMAPIMixin):
    def setUp(self, *args, **kwargs):
        super().setUp(
            am_users=[
                UserFixtures().new_user_example,
                UserFixtures().new_unverified_user_example,
            ]
        )
        self.start_mock_amapi(central_user_db=self.amdb)

        self.skv = init_skv_worker(test_config=self._get_config())

    def _get_config(self) -> Dict[str, Any]:
        return {
            "app_name": "test",
            "mongo_uri": self.settings["mongo_uri"],
            "minimum_delay": 1,
            "time_to_clean_dataset": 30,
            "debug": True,
            "dry_run": False,
            "change_quota": 2,
            "celery": {},
            "amapi": {
                "url": "http://localhost/amapi/",
                "tls_verify": False,
            },
            "gnap_auth_data": {
                "auth_server_url": "http://localhost/auth/",
                "key_name": "app_name",
                "client_jwk": JWK.generate(kid="testkey", kty="EC", size=256).export(as_dict=True),
            },
        }

    @staticmethod
    def _get_all_navet_data():
        return NavetData.parse_obj(MessageSender.get_devel_all_navet_data())

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    def test_update_name(self, mock_get_all_navet_data: MagicMock):
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        cache_user = CacheUser(
            eppn=UserFixtures().new_user_example.eppn,
        )
        navet_data = self.skv.msg_relay.get_all_navet_data(nin="197801011234")
        self.skv.update_name(queue_user=cache_user, navet_data=navet_data)

        got = self.skv.db.get_user_by_eppn(UserFixtures().new_user_example.eppn)

        assert got.given_name == "Testaren Test"
        assert got.surname == "Testsson"

    @pytest.mark.skip(reason="Not implemented yet")
    def test_populate_queue(self):
        self.skv.db_cache.populate(
            am_users=[UserFixtures().mocked_user_standard, UserFixtures().new_user_example], periodicity=1
        )
        self.skv._enqueuing_to_worker_queue()
        got_user1 = self.skv.worker_queue.get()
        assert got_user1["eppn"] == UserFixtures().mocked_user_standard.eppn

        got_user2 = self.skv.worker_queue.get()
        assert got_user2["eppn"] == UserFixtures().new_user_example.eppn  # new_user_example2.eppn
