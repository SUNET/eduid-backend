from datetime import timedelta
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from jwcrypto.jwk import JWK

from eduid.common.clients.amapi_client.testing import MockedAMAPIMixin
from eduid.common.rpc.msg_relay import NavetData
from eduid.common.testing_base import CommonTestCase
from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.user_cleaner.cache import CacheUser
from eduid.workers.msg.tasks import MessageSender
from eduid.workers.user_cleaner.workers.skv import init_skv_worker


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

    def test_populate_queue(self):
        uf = UserFixtures()
        self.skv.db_cache.populate(
            am_users=[uf.new_user_example, uf.new_unverified_user_example],
            periodicity=timedelta(seconds=10),
            minimum_delay=timedelta(seconds=1),
        )
        self.skv._enqueuing_to_worker_queue()
        got_user1 = self.skv.worker_queue.get()
        assert got_user1["eppn"] == uf.new_user_example.eppn

        got_user2 = self.skv.worker_queue.get()
        assert got_user2["eppn"] == uf.new_unverified_user_example.eppn
