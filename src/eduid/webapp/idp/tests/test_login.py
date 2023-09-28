import logging
import os
from datetime import datetime
from typing import Any, Mapping
from unittest.mock import MagicMock, patch

import pytest
from pydantic import HttpUrl, parse_obj_as
from requests import RequestException
from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client

from eduid.userdb import MailAddress
from eduid.vccs.client import VCCSClient
from eduid.webapp.common.authn.utils import get_saml2_config
from eduid.webapp.idp.helpers import IdPAction, IdPMsg
from eduid.webapp.idp.tests.test_api import IdPAPITests
from eduid.webapp.idp.tests.test_app import IdPTests, LoginState
from eduid.workers.am import AmCelerySingleton

logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


class IdPTestLoginAPI(IdPAPITests):
    def test_login_start(self) -> None:
        result = self._try_login()
        assert result.visit_order == [IdPAction.PWAUTH]
        assert result.sso_cookie_val is None

    def test_login_pwauth_wrong_password(self) -> None:
        result = self._try_login(username=self.test_user.eppn, password="bar")
        assert result.visit_order == [IdPAction.PWAUTH, IdPAction.PWAUTH]
        assert result.sso_cookie_val is None
        assert result.pwauth_result is not None
        assert result.pwauth_result.payload["message"] == IdPMsg.wrong_credentials.value

    def test_login_pwauth_right_password(self) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou(self.app.conf.tou_version)

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(username=self.test_user.eppn, password="bar")

        assert result.visit_order == [IdPAction.PWAUTH, IdPAction.FINISHED]
        assert result.sso_cookie_val is not None
        assert result.finished_result is not None
        assert result.finished_result.payload["message"] == IdPMsg.finished.value
        assert result.finished_result.payload["target"] == "https://sp.example.edu/saml2/acs/"
        assert result.finished_result.payload["parameters"]["RelayState"] == self.relay_state
        # TODO: test parsing the SAML response

    def test_login_pwauth_right_password_and_tou_acceptance(self) -> None:
        # Enable AM sync of user to central db for this particular test
        AmCelerySingleton.worker_config.mongo_uri = self.app.conf.mongo_uri

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(username=self.test_user.eppn, password="bar")

        assert result.visit_order == [IdPAction.PWAUTH, IdPAction.TOU, IdPAction.FINISHED]
        assert result.sso_cookie_val is not None
        assert result.finished_result is not None
        assert result.finished_result.payload["message"] == IdPMsg.finished.value
        assert result.finished_result.payload["target"] == "https://sp.example.edu/saml2/acs/"
        assert result.finished_result.payload["parameters"]["RelayState"] == self.relay_state
        # TODO: test parsing the SAML response

    def test_geo_statistics_success(self) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou(self.app.conf.tou_version)

        # enable geo statistics
        self.app.conf.geo_statistics_feature_enabled = True
        self.app.conf.geo_statistics_url = parse_obj_as(HttpUrl, "http://eduid.docker")

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            with patch("requests.post", new_callable=MagicMock) as mock_post:
                result = self._try_login(username=self.test_user.eppn, password="bar")
                assert mock_post.call_count == 1
                assert mock_post.call_args.kwargs.get("json") == {
                    "data": {
                        "user_id": "f58a28aad6b221e6827b8ba4481bb5b6da3833acab5eab43d0f3371b218f6cdc",
                        "client_ip": "127.0.0.1",
                        "known_device": False,
                        "user_agent": {
                            "browser": {"family": "Other"},
                            "os": {"family": "Other"},
                            "device": {"family": "Other"},
                            "sophisticated": {
                                "is_mobile": False,
                                "is_pc": False,
                                "is_tablet": False,
                                "is_touch_capable": False,
                            },
                        },
                    }
                }

        assert result.finished_result is not None
        assert result.finished_result.payload["message"] == IdPMsg.finished.value

    def test_geo_statistics_fail(self) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou(self.app.conf.tou_version)

        # enable geo statistics
        self.app.conf.geo_statistics_feature_enabled = True
        self.app.conf.geo_statistics_url = parse_obj_as(HttpUrl, "http://eduid.docker")

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            with patch("requests.post", new_callable=MagicMock) as mock_post:
                mock_post.side_effect = RequestException("Test Exception")
                result = self._try_login(username=self.test_user.eppn, password="bar")
                assert mock_post.call_count == 1

        assert result.finished_result is not None
        assert result.finished_result.payload["message"] == IdPMsg.finished.value
