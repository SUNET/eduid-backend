import json
from collections.abc import Mapping
from typing import Any, ClassVar
from uuid import UUID, uuid4

import pytest
from pytest_mock import MockerFixture
from werkzeug.test import TestResponse

from eduid.common.config.base import EduidEnvironment
from eduid.userdb.ladok import Ladok, University, UniversityName
from eduid.webapp.common.api.testing import EduidAPITestCase

__author__ = "lundberg"

from eduid.webapp.ladok.app import LadokApp, init_ladok_app
from eduid.webapp.ladok.client import Error, LadokUserInfo, LadokUserInfoResponse
from eduid.webapp.ladok.helpers import LadokMsg


class MockResponse:
    def __init__(self, status_code: int, data: Mapping[str, Any]) -> None:
        self._data = data
        self.status_code = status_code
        self.text = json.dumps(self._data)

    def json(self) -> Mapping[str, Any]:
        return self._data


def _get_university_data() -> dict[str, Any]:
    return {
        "data": {
            "school_names": {
                "ab": {"long_name_sv": "Lärosätesnamn", "long_name_en": "University Name"},
                "cd": {"long_name_sv": "Annat Lärosätesnamn", "long_name_en": "Another University Name"},
            }
        },
        "error": None,
    }


class LadokTests(EduidAPITestCase[LadokApp]):
    api_users: ClassVar[list[str]] = ["hubba-bubba", "hubba-baar"]

    @pytest.fixture(autouse=True)
    def setup(self, setup_api: None) -> None:
        self.test_user_eppn = "hubba-bubba"
        self.test_unverified_user_eppn = "hubba-baar"
        self.ladok_user_external_id = uuid4()

        self.university_data = _get_university_data()

        # remove Ladok data from test user
        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        user.ladok = None
        self.app.central_userdb.save(user)

    def load_app(self, config: Mapping[str, Any]) -> LadokApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_ladok_app("testing", config)

    def _get_base_config(self) -> dict[str, Any]:
        config = super()._get_base_config()
        config["ladok_client"] = {
            "url": "http://localhost",
            "dev_universities": {"DEV": {"long_name_sv": "Testlärosäte", "long_name_en": "Test University"}},
        }
        return config

    @pytest.fixture(scope="class")
    def update_config(self, class_mocker: MockerFixture) -> dict[str, Any]:
        class_mocker.patch("requests.get", return_value=MockResponse(200, _get_university_data()))
        return self._get_base_config()

    def _link_user(self, eppn: str, ladok_name: str) -> TestResponse:
        with self.session_cookie(self.browser, eppn) as browser:
            with browser.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            return browser.post("/link-user", json={"csrf_token": csrf_token, "ladok_name": ladok_name})

    def _unlink_user(self, eppn: str) -> TestResponse:
        with self.session_cookie(self.browser, eppn) as browser:
            with browser.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            return browser.post("/unlink-user", json={"csrf_token": csrf_token})

    def test_authenticate(self) -> None:
        response = self.browser.get("/")
        assert response.status_code == 401
        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            response = browser.get("/")
        self._check_success_response(response, type_="GET_LADOK_SUCCESS")

    def test_get_universities(self) -> None:
        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            response = browser.get("/universities")
        expected_payload = {
            "universities": {
                "ab": {"ladok_name": "ab", "name": {"en": "University Name", "sv": "Lärosätesnamn"}},
                "cd": {"ladok_name": "cd", "name": {"en": "Another University Name", "sv": "Annat Lärosätesnamn"}},
            }
        }
        self._check_success_response(response, type_="GET_LADOK_UNIVERSITIES_SUCCESS", payload=expected_payload)

    def test_link_user(self, mocker: MockerFixture) -> None:
        mock_request_user_sync = mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_response = mocker.patch("requests.post")
        mock_request_user_sync.side_effect = self.request_user_sync

        ladok_user_external_id_str = str(self.ladok_user_external_id)
        user_info = LadokUserInfo(
            external_id=ladok_user_external_id_str,
            esi=f"urn:schac:personalUniqueCode:int:esi:ladok.se:externtstudentuid-{ladok_user_external_id_str}",
            is_student=None,
        )
        mock_response.return_value = MockResponse(
            status_code=200, data=LadokUserInfoResponse(error=None, data=user_info).model_dump(by_alias=True)
        )

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.identities.nin is not None
        assert user.identities.nin.is_verified is True

        ladok_name = "ab"
        response = self._link_user(eppn=self.test_user_eppn, ladok_name=ladok_name)
        self._check_success_response(response, type_="POST_LADOK_LINK_USER_SUCCESS")

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok is not None
        assert user.ladok.external_id == self.ladok_user_external_id
        assert user.ladok.university.ladok_name == ladok_name
        assert user.ladok.university.name.sv == self.app.ladok_client.universities[ladok_name].name.sv
        assert user.ladok.university.name.en == self.app.ladok_client.universities[ladok_name].name.en

        log_docs = self.app.proofing_log._get_documents_by_attr("eduPersonPrincipalName", self.test_user_eppn)
        assert len(log_docs) == 1

    def test_link_user_error_response_from_worker(self, mocker: MockerFixture) -> None:
        mock_response = mocker.patch("requests.post")
        error = Error(id="internal_server_error", details="some longer error message")
        mock_response.return_value = MockResponse(
            status_code=200, data=LadokUserInfoResponse(error=error, data=None).model_dump(by_alias=True)
        )

        ladok_name = "ab"
        response = self._link_user(eppn=self.test_user_eppn, ladok_name=ladok_name)
        self._check_error_response(response, type_="POST_LADOK_LINK_USER_FAIL", msg=LadokMsg.no_ladok_data)

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok is None

        log_docs = self.app.proofing_log._get_documents_by_attr("eduPersonPrincipalName", self.test_user_eppn)
        assert len(log_docs) == 0

    def test_link_user_no_nin(self) -> None:
        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_unverified_user_eppn)
        assert user.identities.nin is None

        ladok_name = "ab"
        response = self._link_user(eppn=self.test_unverified_user_eppn, ladok_name=ladok_name)
        self._check_error_response(response, type_="POST_LADOK_LINK_USER_FAIL", msg=LadokMsg.no_verified_nin)

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_unverified_user_eppn)
        assert user.ladok is None

        log_docs = self.app.proofing_log._get_documents_by_attr(
            "eduPersonPrincipalName", self.test_unverified_user_eppn
        )
        assert len(log_docs) == 0

    def test_unlink_user(self, mocker: MockerFixture) -> None:
        mock_request_user_sync = mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_request_user_sync.side_effect = self.request_user_sync

        # set ladok data for user
        university = University(ladok_name="ab", name=UniversityName(sv="namn", en="name"))
        ladok = Ladok(external_id=self.ladok_user_external_id, university=university)
        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        user.ladok = ladok
        self.app.central_userdb.save(user)

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok is not None
        assert user.ladok.external_id == self.ladok_user_external_id
        assert user.ladok.university.ladok_name == university.ladok_name

        response = self._unlink_user(eppn=self.test_user_eppn)
        self._check_success_response(response, type_="POST_LADOK_UNLINK_USER_SUCCESS", msg=LadokMsg.user_unlinked)

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok is None

    def test_unlink_user_no_op(self) -> None:
        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok is None

        response = self._unlink_user(eppn=self.test_user_eppn)
        self._check_success_response(response, type_="POST_LADOK_UNLINK_USER_SUCCESS", msg=LadokMsg.user_unlinked)

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok is None


class LadokDevTests(EduidAPITestCase[LadokApp]):
    api_users: ClassVar[list[str]] = ["hubba-bubba", "hubba-baar"]

    @pytest.fixture(autouse=True)
    def setup(self, setup_api: None) -> None:
        self.test_user_eppn = "hubba-bubba"
        self.test_unverified_user_eppn = "hubba-baar"
        self.ladok_user_external_id = uuid4()

    def load_app(self, config: Mapping[str, Any]) -> LadokApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_ladok_app("testing", config)

    @pytest.fixture(scope="class")
    def update_config(self) -> dict[str, Any]:
        config = self._get_base_config()
        config["environment"] = EduidEnvironment.dev.value
        config["ladok_client"] = {
            "url": "http://localhost",
            "dev_universities": {"DEV": {"sv": "Testlärosäte", "en": "Test University"}},
        }
        config["magic_cookie_name"] = "magic-cookie"
        config["magic_cookie"] = "magic-cookie"
        config["dev_fake_users_in"] = ["DEV"]
        return config

    def test_link_user_backdoor(self, mocker: MockerFixture) -> None:
        mock_request_user_sync = mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_request_user_sync.side_effect = self.request_user_sync

        ladok_name = "DEV"
        with self.session_cookie_and_magic_cookie(self.browser, self.test_user.eppn) as browser:
            with browser.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            response = browser.post("/link-user", json={"csrf_token": csrf_token, "ladok_name": ladok_name})
        self._check_success_response(response, type_="POST_LADOK_LINK_USER_SUCCESS")

        user = self.app.central_userdb.get_user_by_eppn(eppn=self.test_user_eppn)
        assert user.ladok is not None
        assert user.ladok.external_id == UUID("00000000-1111-2222-3333-444444444444")
        assert user.ladok.university.ladok_name == ladok_name
        assert user.ladok.university.name.sv == self.app.ladok_client.universities[ladok_name].name.sv
        assert user.ladok.university.name.en == self.app.ladok_client.universities[ladok_name].name.en

        log_docs = self.app.proofing_log._get_documents_by_attr("eduPersonPrincipalName", self.test_user_eppn)
        assert len(log_docs) == 1
