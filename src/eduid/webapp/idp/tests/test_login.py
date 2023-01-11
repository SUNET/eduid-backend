import logging
import os
from datetime import datetime
from typing import Any
from collections.abc import Mapping

import pytest
from unittest.mock import MagicMock, patch
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


class IdPTestLogin(IdPTests):
    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config = super().update_config(config)
        config.update(
            {
                "signup_link": "TEST-SIGNUP-LINK",
                "log_level": "DEBUG",
                "enable_legacy_template_mode": True,
            }
        )
        return config

    def test_display_of_login_page(self) -> None:
        next_url = "/back-to-test-marker"

        _session_id: str
        info: Mapping[str, Any]
        (_session_id, info) = self.saml2_client.prepare_for_authenticate(
            entityid=self.idp_entity_id,
            relay_state=next_url,
            binding=BINDING_HTTP_REDIRECT,
        )

        path = self._extract_path_from_info(info)

        response = self.browser.get(path)

        assert response.status_code == 302
        # check that we were sent to the login screen
        redirect_loc = self._extract_path_from_response(response)
        response2 = self.browser.get(redirect_loc)

        body = response2.data.decode("utf-8")

        assert self.app.conf.signup_link in body

    def test_submitting_wrong_credentials(self) -> None:
        result = self._try_login()

        assert result.reached_state == LoginState.S2_VERIFY

        # check that we were sent back to the login screen
        redirect_loc = self._extract_path_from_response(result.response)
        assert redirect_loc.startswith("/sso/redirect?ref=")

        # TODO: Verify that no SSO session was created, and no credentials were logged as used in the session

    def test_successful_authentication(self) -> None:
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        assert result.reached_state == LoginState.S5_LOGGED_IN

        authn_response = self.parse_saml_authn_response(result.response)
        session_info = authn_response.session_info()
        attributes: dict[str, list[Any]] = session_info["ava"]

        assert "eduPersonPrincipalName" in attributes
        assert attributes["eduPersonPrincipalName"] == [f"hubba-bubba@{self.app.conf.default_eppn_scope}"]

    def test_ForceAuthn_with_existing_SSO_session(self) -> None:
        # Patch the VCCSClient so we do not need a vccs server
        self.add_test_user_tou(self.test_user)

        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        assert result.reached_state == LoginState.S5_LOGGED_IN

        authn_response = self.parse_saml_authn_response(result.response)
        session_info = authn_response.session_info()
        attributes: dict[str, list[Any]] = session_info["ava"]

        assert "eduPersonPrincipalName" in attributes
        assert attributes["eduPersonPrincipalName"] == [f"hubba-bubba@{self.app.conf.default_eppn_scope}"]

        logger.info(
            "\n\n\n\n" + "#" * 80 + "\n" + 'Logging in again with ForceAuthn="true"\n' + "#" * 80 + "\n" + "\n\n\n\n"
        )

        # Log in again, with ForceAuthn="true"
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result2 = self._try_login(force_authn=True)

        authn_response2 = self.parse_saml_authn_response(result2.response)

        # Make sure the second response isn't referring to the first login request
        assert authn_response.in_response_to != authn_response2.in_response_to

    def test_terminated_user(self) -> None:
        user = self.amdb.get_user_by_eppn(self.test_user.eppn)
        user.terminated = datetime.fromisoformat("2020-02-25T15:52:59.745")
        self.amdb.save(user)

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        assert result.reached_state == LoginState.S3_REDIRECT_LOGGED_IN
        cookie = result.response.headers["Set-Cookie"]
        assert f"{self.app.conf.sso_cookie.key}=;" in cookie
        assert "expires=Thu, 01 Jan 1970 00:00:00 GMT" in cookie

    def test_with_unknown_sp(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="UNKNOWN_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        assert result.reached_state == LoginState.S3_REDIRECT_LOGGED_IN
        assert b"SAML error: Unknown Service Provider" in result.response.data

    def test_sso_to_unknown_sp(self) -> None:
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        assert result.reached_state == LoginState.S5_LOGGED_IN

        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="UNKNOWN_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # Don't patch VCCS here to ensure a SSO is done, not a password authentication
        result2 = self._try_login(saml2_client=saml2_client)

        assert result2.reached_state == LoginState.S0_REDIRECT
        assert b"SAML error: Unknown Service Provider" in result2.response.data
        cookies = result2.response.headers["Set-Cookie"]
        # Ensure the pre-existing IdP SSO cookie wasn't touched
        assert self.app.conf.sso_cookie.key not in cookies

    @pytest.mark.skip("Actions app has been removed")
    def test_with_authncontext(self) -> None:
        """
        Request REFEDS_MFA, but the test user does not have any MFA credentials.
        The user can still login using external MFA though, so this test expects to be redirected to actions."""
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            # request MFA, but the test user does not have any MFA credentials
            req_authn_context = {"authn_context_class_ref": ["https://refeds.org/profile/mfa"], "comparison": "exact"}
            result = self._try_login(authn_context=req_authn_context)

        assert result.reached_state == LoginState.S3_REDIRECT_LOGGED_IN

    def test_eduperson_targeted_id(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="COCO_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        assert result.reached_state == LoginState.S5_LOGGED_IN

        authn_response = self.parse_saml_authn_response(result.response, saml2_client=saml2_client)
        session_info = authn_response.session_info()
        attributes: dict[str, list[Any]] = session_info["ava"]
        assert "eduPersonTargetedID" in attributes
        assert attributes["eduPersonTargetedID"] == ["71a13b105e83aa69c31f41b08ea83694e0fae5f368d17ef18ba59e0f9e407ec9"]

    def test_schac_personal_unique_code_esi(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="ESI_COCO_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        assert result.reached_state == LoginState.S5_LOGGED_IN

        authn_response = self.parse_saml_authn_response(result.response, saml2_client=saml2_client)
        session_info = authn_response.session_info()
        attributes: dict[str, list[Any]] = session_info["ava"]
        requested_attributes = ["schacPersonalUniqueCode", "eduPersonTargetedID"]
        # make sure we only release the two requested attributes
        assert [attr for attr in attributes if attr not in requested_attributes] == []
        assert attributes["eduPersonTargetedID"] == ["75fae1234b2e3304bfd069c1296ccd7af97f2cc95855e2e0ce3577d1f70a0088"]
        assert self.test_user.ladok is not None
        assert attributes["schacPersonalUniqueCode"] == [
            f"{self.app.conf.esi_ladok_prefix}{self.test_user.ladok.external_id}"
        ]

    def test_pairwise_id(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="COCO_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        assert result.reached_state == LoginState.S5_LOGGED_IN

        authn_response = self.parse_saml_authn_response(result.response, saml2_client=saml2_client)
        session_info = authn_response.session_info()
        attributes: dict[str, list[Any]] = session_info["ava"]
        assert attributes["pairwise-id"] == [
            "36382d115a9b7d8c27cc9eed94aab0ea6cc16a8becc5a468922e36e5a351f8f9@test.scope"
        ]

    def test_subject_id(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        assert result.reached_state == LoginState.S5_LOGGED_IN

        authn_response = self.parse_saml_authn_response(result.response, saml2_client=saml2_client)
        session_info = authn_response.session_info()
        attributes: dict[str, list[Any]] = session_info["ava"]
        assert attributes["subject-id"] == ["hubba-bubba@test.scope"]

    def test_mail_local_address(self) -> None:
        # add another mail address to the test user
        self.test_user.mail_addresses.add(MailAddress(email="test@example.com", is_verified=True))
        self.request_user_sync(self.test_user)

        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        assert result.reached_state == LoginState.S5_LOGGED_IN

        authn_response = self.parse_saml_authn_response(result.response, saml2_client=saml2_client)
        session_info = authn_response.session_info()
        attributes: dict[str, list[Any]] = session_info["ava"]
        assert attributes["mailLocalAddress"] == ["johnsmith@example.com", "test@example.com"]

    def test_successful_authentication_alternative_acs(self) -> None:
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(assertion_consumer_service_url="https://localhost:8080/acs/")

        assert result.reached_state == LoginState.S5_LOGGED_IN
        assert 'form action="https://localhost:8080/acs/" method="post"' in result.response.data.decode("utf-8")


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
