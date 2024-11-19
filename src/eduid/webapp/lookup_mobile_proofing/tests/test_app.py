import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

from eduid.common.config.base import EduidEnvironment
from eduid.common.rpc.exceptions import LookupMobileTaskFailed
from eduid.userdb import User
from eduid.userdb.testing import SetupConfig
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.lookup_mobile_proofing.app import MobileProofingApp, init_lookup_mobile_proofing_app
from eduid.webapp.lookup_mobile_proofing.helpers import MobileMsg

__author__ = "lundberg"


class LookupMobileProofingTests(EduidAPITestCase[MobileProofingApp]):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self, config: SetupConfig | None = None) -> None:
        self.test_user_eppn = "hubba-baar"
        self.test_user_nin = "199001023456"
        fifteen_years_ago = datetime.now() - timedelta(days=15 * 365)
        self.test_user_nin_underage = f"{fifteen_years_ago.year}01023456"

        if config is None:
            config = SetupConfig()
        config.users = ["hubba-baar"]
        super().setUp(config=config)

    def load_app(self, config: Mapping[str, Any]) -> MobileProofingApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_lookup_mobile_proofing_app("testing", config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                "environment": "dev",
                "magic_cookie": "",
                "magic_cookie_name": "",
            },
        )
        return config

    def _check_nin_verified_ok_no_proofing_state(self, user: User, number: str | None = None) -> None:
        nin_number = number or self.test_user_nin
        assert user.identities.nin is not None
        assert user.identities.nin.number == nin_number
        assert user.identities.nin.created_by == "lookup_mobile_proofing"
        assert user.identities.nin.verified_by == "lookup_mobile_proofing"
        assert user.identities.nin.is_verified is True
        assert self.app.proofing_log.db_count() == 1

    def _check_nin_not_verified_no_proofing_state(self, user: User, number: str | None = None) -> None:
        nin_number = number or self.test_user_nin
        assert user.identities.nin is not None
        assert user.identities.nin.number == nin_number
        assert user.identities.nin.created_by == "lookup_mobile_proofing"
        assert user.identities.nin.is_verified is False
        assert self.app.proofing_log.db_count() == 0

    def test_authenticate(self) -> None:
        response = self.browser.get("/proofing")
        self.assertEqual(response.status_code, 401)
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get("/proofing")
        self.assertEqual(response.status_code, 200)  # Authenticated request

    @patch("eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_proofing_flow(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock, mock_find_nin_by_mobile: MagicMock
    ) -> None:
        mock_find_nin_by_mobile.return_value = self.test_user_nin
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get("/proofing").data)
        self.assertEqual(response["type"], "GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS")

        csrf_token = response["payload"]["csrf_token"]

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {"nin": self.test_user_nin, "csrf_token": csrf_token}
            response = browser.post("/proofing", data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response["type"], "POST_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS")
        self.assertEqual(response["payload"]["success"], True)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self._check_nin_verified_ok_no_proofing_state(user=user)

    @patch("eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_proofing_flow_underage(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock, mock_find_nin_by_mobile: MagicMock
    ) -> None:
        mock_find_nin_by_mobile.return_value = self.test_user_nin_underage
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get("/proofing").data)
        self.assertEqual(response["type"], "GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS")

        csrf_token = response["payload"]["csrf_token"]

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {"nin": self.test_user_nin_underage, "csrf_token": csrf_token}
            response = browser.post("/proofing", data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response["type"], "POST_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS")
        self.assertEqual(response["payload"]["success"], True)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self._check_nin_verified_ok_no_proofing_state(user=user, number=self.test_user_nin_underage)

    @patch("eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_proofing_flow_no_match(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock, mock_find_nin_by_mobile: MagicMock
    ) -> None:
        mock_find_nin_by_mobile.return_value = None
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get("/proofing").data)
        self.assertEqual(response["type"], "GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS")

        csrf_token = response["payload"]["csrf_token"]

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {"nin": self.test_user_nin, "csrf_token": csrf_token}
            response = browser.post("/proofing", data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response["type"], "POST_LOOKUP_MOBILE_PROOFING_PROOFING_FAIL")

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self._check_nin_not_verified_no_proofing_state(user=user)

    @patch("eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_proofing_flow_LookupMobileTaskFailed(
        self, mock_request_user_sync: MagicMock, mock_get_all_navet_data: MagicMock, mock_find_nin_by_mobile: MagicMock
    ) -> None:
        mock_find_nin_by_mobile.side_effect = LookupMobileTaskFailed("Test Exception")
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get("/proofing").data)
        self.assertEqual(response["type"], "GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS")

        csrf_token = response["payload"]["csrf_token"]

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {"nin": self.test_user_nin, "csrf_token": csrf_token}
            response = browser.post("/proofing", data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual("POST_LOOKUP_MOBILE_PROOFING_PROOFING_FAIL", response["type"])
        self.assertEqual(MobileMsg.lookup_error.value, response["payload"]["message"])

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self._check_nin_not_verified_no_proofing_state(user=user)

    @patch("eduid.webapp.common.api.helpers.get_reference_nin_from_navet_data")
    @patch("eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_postal_address")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_proofing_flow_no_match_backdoor(
        self,
        mock_request_user_sync: MagicMock,
        mock_get_postal_address: MagicMock,
        mock_find_nin_by_mobile: MagicMock,
        mock_reference_nin: MagicMock,
    ) -> None:
        mock_find_nin_by_mobile.return_value = None
        mock_get_postal_address.return_value = None
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_reference_nin.return_value = None

        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic-cookie"

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get("/proofing").data)
        self.assertEqual(response["type"], "GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS")

        csrf_token = response["payload"]["csrf_token"]

        with self.session_cookie_and_magic_cookie(self.browser, eppn=self.test_user_eppn) as browser:
            data = {"nin": self.test_user_nin_underage, "csrf_token": csrf_token}
            response = browser.post("/proofing", data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response["type"], "POST_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS")
        self.assertEqual(response["payload"]["success"], True)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self._check_nin_verified_ok_no_proofing_state(user=user, number=self.test_user_nin_underage)

    @patch("eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_postal_address")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_proofing_flow_no_match_backdoor_code_in_pro(
        self, mock_request_user_sync: MagicMock, mock_get_postal_address: MagicMock, mock_find_nin_by_mobile: MagicMock
    ) -> None:
        mock_find_nin_by_mobile.return_value = None
        mock_get_postal_address.return_value = None
        mock_request_user_sync.side_effect = self.request_user_sync

        self.app.conf.environment = EduidEnvironment("production")
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic-cookie"

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get("/proofing").data)
        self.assertEqual(response["type"], "GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS")

        csrf_token = response["payload"]["csrf_token"]

        with self.session_cookie_and_magic_cookie(self.browser, eppn=self.test_user_eppn) as browser:
            data = {"nin": self.test_user_nin, "csrf_token": csrf_token}
            response = browser.post("/proofing", data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response["type"], "POST_LOOKUP_MOBILE_PROOFING_PROOFING_FAIL")

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self._check_nin_not_verified_no_proofing_state(user=user)

    @patch("eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_postal_address")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_proofing_flow_no_match_backdoor_code_unconfigured(
        self, mock_request_user_sync: MagicMock, mock_get_postal_address: MagicMock, mock_find_nin_by_mobile: MagicMock
    ) -> None:
        mock_find_nin_by_mobile.return_value = None
        mock_get_postal_address.return_value = None
        mock_request_user_sync.side_effect = self.request_user_sync

        self.app.conf.magic_cookie = ""
        self.app.conf.magic_cookie_name = "magic-cookie"

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get("/proofing").data)
        self.assertEqual(response["type"], "GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS")

        csrf_token = response["payload"]["csrf_token"]

        with self.session_cookie_and_magic_cookie(self.browser, self.test_user_eppn) as browser:
            data = {"nin": self.test_user_nin, "csrf_token": csrf_token}
            response = browser.post("/proofing", data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response["type"], "POST_LOOKUP_MOBILE_PROOFING_PROOFING_FAIL")

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self._check_nin_not_verified_no_proofing_state(user=user)

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_relations_to")
    @patch("eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_proofing_flow_relation(
        self,
        mock_request_user_sync: MagicMock,
        mock_get_all_navet_data: MagicMock,
        mock_find_nin_by_mobile: MagicMock,
        mock_get_relations_to: MagicMock,
    ) -> None:
        mock_get_relations_to.return_value = ["MO"]
        mock_find_nin_by_mobile.return_value = "197001021234"
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get("/proofing").data)
        self.assertEqual(response["type"], "GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS")

        csrf_token = response["payload"]["csrf_token"]

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {"nin": self.test_user_nin_underage, "csrf_token": csrf_token}
            response = browser.post("/proofing", data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        assert response["type"] == "POST_LOOKUP_MOBILE_PROOFING_PROOFING_FAIL"
        assert response["payload"]["message"] == MobileMsg.no_match.value

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self._check_nin_not_verified_no_proofing_state(user=user, number=self.test_user_nin_underage)

    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_relations_to")
    @patch("eduid.common.rpc.lookup_mobile_relay.LookupMobileRelay.find_nin_by_mobile")
    @patch("eduid.common.rpc.msg_relay.MsgRelay.get_all_navet_data")
    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_proofing_flow_relation_no_match(
        self,
        mock_request_user_sync: MagicMock,
        mock_get_all_navet_data: MagicMock,
        mock_find_nin_by_mobile: MagicMock,
        mock_get_relations_to: MagicMock,
    ) -> None:
        mock_get_relations_to.return_value = []
        mock_find_nin_by_mobile.return_value = "197001021234"
        mock_get_all_navet_data.return_value = self._get_all_navet_data()
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get("/proofing").data)
        self.assertEqual(response["type"], "GET_LOOKUP_MOBILE_PROOFING_PROOFING_SUCCESS")

        csrf_token = response["payload"]["csrf_token"]

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {"nin": self.test_user_nin_underage, "csrf_token": csrf_token}
            response = browser.post("/proofing", data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response["type"], "POST_LOOKUP_MOBILE_PROOFING_PROOFING_FAIL")

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self._check_nin_not_verified_no_proofing_state(user=user, number=self.test_user_nin_underage)
