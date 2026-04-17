import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any, cast

import pytest
from bson import ObjectId
from pytest_mock import MockerFixture
from requests import RequestException
from saml2.client import Saml2Client

from eduid.common.misc.timeutil import utc_now
from eduid.common.models.saml2 import EduidAuthnContextClass
from eduid.userdb import MailAddress
from eduid.userdb.credentials import Password
from eduid.userdb.maccapi.userdb import ManagedAccount
from eduid.userdb.mail import MailAddressList
from eduid.vccs.client import VCCSClient
from eduid.webapp.common.api.testing import CSRFTestClient
from eduid.webapp.common.authn.utils import get_saml2_config
from eduid.webapp.common.session.namespaces import LoginApplication, RequestRef
from eduid.webapp.idp.helpers import IdPAction, IdPMsg
from eduid.webapp.idp.other_device.data import OtherDeviceState
from eduid.webapp.idp.tests.test_api import (
    FinishedResultAPI,
    IdPAPITests,
    LoginResultAPI,
    NextResult,
    PwAuthResult,
    TestUser,
)
from eduid.workers.am.common import AmCelerySingleton

logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


class IdPTestLoginAPI(IdPAPITests):
    def test_login_start(self) -> None:
        result = self._try_login(test_user=TestUser(eppn=None, password=None))

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH],
            sso_cookie_val=None,
        )

    def test_login_pwauth_wrong_password(self, mocker: MockerFixture) -> None:
        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=False)
        result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.USERNAMEPWAUTH],
            sso_cookie_val=None,
            pwauth_result=PwAuthResult(
                payload={
                    "message": IdPMsg.wrong_credentials.value,
                }
            ),
        )

    def test_login_pwauth_no_username(self) -> None:
        result = self._try_login(username=False)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.USERNAMEPWAUTH],
            sso_cookie_val=None,
            pwauth_result=PwAuthResult(
                payload={
                    "message": IdPMsg.wrong_credentials.value,
                }
            ),
        )

    def test_login_pwauth_right_password(self, mocker: MockerFixture) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(
                payload={
                    "message": IdPMsg.finished.value,
                    "target": "https://sp.example.edu/saml2/acs/",
                    "parameters": {"RelayState": self.relay_state},
                }
            ),
        )

        attributes = self.get_attributes(result)

        assert "eduPersonPrincipalName" in attributes
        assert attributes["eduPersonPrincipalName"] == [f"hubba-bubba@{self.app.conf.default_eppn_scope}"]

    def test_login_pwauth_right_password_and_tou_acceptance(self, mocker: MockerFixture) -> None:
        # Enable AM sync of user to central db for this particular test
        AmCelerySingleton.worker_config.mongo_uri = self.app.conf.mongo_uri

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.TOU, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(
                payload={
                    "message": IdPMsg.finished.value,
                    "target": "https://sp.example.edu/saml2/acs/",
                    "parameters": {"RelayState": self.relay_state},
                }
            ),
        )

        attributes = self.get_attributes(result)
        assert "eduPersonPrincipalName" in attributes
        assert attributes["eduPersonPrincipalName"] == [f"hubba-bubba@{self.app.conf.default_eppn_scope}"]

    def test_login_mfaauth(self, mocker: MockerFixture) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # add security key to user
        self.add_test_user_security_key()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[
                IdPAction.USERNAMEPWAUTH,
                IdPAction.MFA,
                IdPAction.FINISHED,
            ],
            finish_result=FinishedResultAPI(
                payload={
                    "message": IdPMsg.finished.value,
                    "target": "https://sp.example.edu/saml2/acs/",
                    "parameters": {"RelayState": self.relay_state},
                }
            ),
        )

        attributes = self.get_attributes(result)
        assert "eduPersonPrincipalName" in attributes
        assert attributes["eduPersonPrincipalName"] == [f"hubba-bubba@{self.app.conf.default_eppn_scope}"]

    def test_login_no_mandatory_mfa(self, mocker: MockerFixture) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # add security key to user
        self.add_test_user_security_key(always_use_security_key=False)

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[
                IdPAction.USERNAMEPWAUTH,
                IdPAction.FINISHED,
            ],
            finish_result=FinishedResultAPI(
                payload={
                    "message": IdPMsg.finished.value,
                    "target": "https://sp.example.edu/saml2/acs/",
                    "parameters": {"RelayState": self.relay_state},
                }
            ),
        )

        attributes = self.get_attributes(result)
        assert "eduPersonPrincipalName" in attributes
        assert attributes["eduPersonPrincipalName"] == [f"hubba-bubba@{self.app.conf.default_eppn_scope}"]

    def test_login_no_mandatory_mfa_with_mfa_accr(self, mocker: MockerFixture) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # add security key to user
        self.add_test_user_security_key(always_use_security_key=False)

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(
            authn_context={
                "authn_context_class_ref": [EduidAuthnContextClass.REFEDS_MFA.value],
                "comparison": "exact",
            }
        )
        self._check_login_result(
            result=result,
            visit_order=[
                IdPAction.USERNAMEPWAUTH,
                IdPAction.MFA,
                IdPAction.FINISHED,
            ],
            finish_result=FinishedResultAPI(
                payload={
                    "message": IdPMsg.finished.value,
                    "target": "https://sp.example.edu/saml2/acs/",
                    "parameters": {"RelayState": self.relay_state},
                }
            ),
        )

        attributes = self.get_attributes(result)
        assert "eduPersonPrincipalName" in attributes
        assert attributes["eduPersonPrincipalName"] == [f"hubba-bubba@{self.app.conf.default_eppn_scope}"]

    def test_login_missing_attributes(self, mocker: MockerFixture) -> None:
        # pre-accept ToU for this test
        user, _ = self.add_test_user_tou()

        # remove mail address from user to simulate missing attribute
        user.mail_addresses = MailAddressList()
        self.request_user_sync(user)

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(
                payload={
                    "missing_attributes": [
                        {"friendly_name": "mailLocalAddress", "name": "urn:oid:2.16.840.1.113730.3.1.13"}
                    ]
                }
            ),
        )

        attributes = self.get_attributes(result)
        assert attributes["mailLocalAddress"] == []

    def test_ForceAuthn_with_existing_SSO_session(self, mocker: MockerFixture) -> None:
        # add security key to user
        self.add_test_user_security_key()
        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        for accr in [None, EduidAuthnContextClass.PASSWORD_PT, EduidAuthnContextClass.REFEDS_MFA]:
            requested_authn_context = None
            if accr is not None:
                requested_authn_context = {"authn_context_class_ref": [accr.value]}

            # pre-accept ToU for this test
            self.add_test_user_tou()

            result = self._try_login()

            assert result.finished_result is not None
            authn_response = self.parse_saml_authn_response(result.finished_result)
            session_info = authn_response.session_info()
            attributes: dict[str, list[Any]] = session_info["ava"]

            assert "eduPersonPrincipalName" in attributes
            assert attributes["eduPersonPrincipalName"] == [f"hubba-bubba@{self.app.conf.default_eppn_scope}"]

            # Log in again, with ForceAuthn="true"
            result2 = self._try_login(
                force_authn=True, authn_context=requested_authn_context, sso_cookie_val=result.sso_cookie_val
            )

            if accr is EduidAuthnContextClass.REFEDS_MFA:
                assert result2.visit_order == [
                    IdPAction.MFA,
                    IdPAction.USERNAMEPWAUTH,
                    IdPAction.FINISHED,
                ], f"Actual visit order: {result2.visit_order}"
            else:
                assert result2.finished_result is not None
                authn_response2 = self.parse_saml_authn_response(result2.finished_result)
                # Make sure the second response isn't referring to the first login request
                assert authn_response.in_response_to != authn_response2.in_response_to

    def test_login_other_device(self, mocker: MockerFixture) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # initiate other device login flow
        device_1_result1 = self._try_login(other_device=True)
        assert device_1_result1.ref is not None
        assert device_1_result1.other_device1_result is not None

        # "read" qr code and start device 2 flow
        state_id = device_1_result1.other_device1_result.payload.get("state_id")
        assert state_id is not None
        qr_url = device_1_result1.other_device1_result.payload.get("qr_url")
        assert qr_url is not None
        assert qr_url.endswith(state_id) is True

        device2 = cast(CSRFTestClient, self.app.test_client())
        device_2_result1 = self._call_other_device2(
            device=device2, target="http://test.localhost/use_other_2", state_id=state_id
        )

        assert device_2_result1.payload.get("state") == OtherDeviceState.IN_PROGRESS
        login_ref = device_2_result1.payload.get("login_ref")
        assert login_ref is not None

        # login in with device 2
        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        device_2_result2 = self._try_login(device=device2, login_ref=login_ref)

        self._check_login_result(
            result=device_2_result2,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
        )

        # after login with device 2, retrieve the response code
        device_2_result3 = self._call_other_device2(
            device=device2,
            target="http://test.localhost/use_other_2",
            state_id=state_id,
        )
        assert device_2_result3.payload.get("state") == OtherDeviceState.AUTHENTICATED.value
        response_code = device_2_result3.payload.get("response_code")
        assert response_code is not None

        # input the response code with device 1
        device_1_result2 = self._call_other_device1(
            device=self.browser,
            target="http://test.localhost/use_other_1",
            ref=device_1_result1.ref,
            response_code=response_code,
        )
        assert device_1_result2.payload.get("state") == OtherDeviceState.FINISHED.value

    def test_login_other_device_with_accr(self, mocker: MockerFixture) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # add security key to user
        self.add_test_user_security_key()

        # initiate other device login flow
        device_1_result1 = self._try_login(
            other_device=True,
            authn_context={
                "authn_context_class_ref": [EduidAuthnContextClass.REFEDS_MFA.value],
                "comparison": "exact",
            },
        )
        assert device_1_result1.ref is not None
        assert device_1_result1.other_device1_result is not None

        # "read" qr code and start device 2 flow
        state_id = device_1_result1.other_device1_result.payload.get("state_id")
        assert state_id is not None
        qr_url = device_1_result1.other_device1_result.payload.get("qr_url")
        assert qr_url is not None
        assert qr_url.endswith(state_id) is True

        device2 = cast(CSRFTestClient, self.app.test_client())
        device_2_result1 = self._call_other_device2(
            device=device2, target="http://test.localhost/use_other_2", state_id=state_id
        )

        assert device_2_result1.payload.get("state") == OtherDeviceState.IN_PROGRESS
        login_ref = device_2_result1.payload.get("login_ref")
        assert login_ref is not None

        # login in with device 2
        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        device_2_result2 = self._try_login(device=device2, login_ref=login_ref)

        self._check_login_result(
            result=device_2_result2,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.MFA, IdPAction.FINISHED],
        )

        # after login with device 2, retrieve the response code
        device_2_result3 = self._call_other_device2(
            device=device2,
            target="http://test.localhost/use_other_2",
            state_id=state_id,
        )
        assert device_2_result3.payload.get("state") == OtherDeviceState.AUTHENTICATED.value
        response_code = device_2_result3.payload.get("response_code")
        assert response_code is not None

        # input the response code with device 1
        device_1_result2 = self._call_other_device1(
            device=self.browser,
            target="http://test.localhost/use_other_1",
            ref=device_1_result1.ref,
            response_code=response_code,
        )
        assert device_1_result2.payload.get("state") == OtherDeviceState.FINISHED.value

    def test_terminated_user(self, mocker: MockerFixture) -> None:
        user = self.amdb.get_user_by_eppn(self.test_user.eppn)
        user.terminated = datetime.fromisoformat("2020-02-25T15:52:59.745")
        self.amdb.save(user)

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH],
            error={"payload": {"message": IdPMsg.user_terminated.value}},
        )

    def test_with_unknown_sp(self, mocker: MockerFixture) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="UNKNOWN_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH],
            error={"status_code": 400, "status": "400 BAD REQUEST", "message": "SAML error: Unknown Service Provider"},
        )

    def test_sso_to_unknown_sp(self, mocker: MockerFixture) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
        )

        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="UNKNOWN_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # Don't patch VCCS here to ensure a SSO is done, not a password authentication
        result2 = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result2,
            visit_order=[],
            sso_cookie_val=None,
            error={"status_code": 400, "status": "400 BAD REQUEST", "message": "SAML error: Unknown Service Provider"},
        )

    def test_eduperson_targeted_id(self, mocker: MockerFixture) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="COCO_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)
        assert "eduPersonTargetedID" in attributes
        assert attributes["eduPersonTargetedID"] == ["71a13b105e83aa69c31f41b08ea83694e0fae5f368d17ef18ba59e0f9e407ec9"]

    def test_schac_personal_unique_code_esi(self, mocker: MockerFixture) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="ESI_COCO_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)

        requested_attributes = ["schacPersonalUniqueCode", "eduPersonTargetedID"]
        # make sure we only release the two requested attributes
        assert [attr for attr in attributes if attr not in requested_attributes] == []
        assert attributes["eduPersonTargetedID"] == ["75fae1234b2e3304bfd069c1296ccd7af97f2cc95855e2e0ce3577d1f70a0088"]
        assert self.test_user.ladok is not None
        assert attributes["schacPersonalUniqueCode"] == [
            f"{self.app.conf.esi_ladok_prefix}{self.test_user.ladok.external_id}"
        ]

    def test_pairwise_id(self, mocker: MockerFixture) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="COCO_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)

        assert attributes["pairwise-id"] == [
            "36382d115a9b7d8c27cc9eed94aab0ea6cc16a8becc5a468922e36e5a351f8f9@test.scope"
        ]

    def test_subject_id(self, mocker: MockerFixture) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)
        assert attributes["subject-id"] == ["hubba-bubba@test.scope"]

    def test_mail_local_address(self, mocker: MockerFixture) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # add another mail address to the test user
        self.add_test_user_mail_address(MailAddress(email="test@example.com", is_verified=True))

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)

        assert attributes["mailLocalAddress"] == ["johnsmith@example.com", "test@example.com"]

    def test_successful_authentication_alternative_acs(self, mocker: MockerFixture) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(assertion_consumer_service_url="https://localhost:8080/acs/")

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"target": "https://localhost:8080/acs/"}),
        )

    def test_geo_statistics_success(self, mocker: MockerFixture) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # enable geo statistics
        self.app.conf.geo_statistics_feature_enabled = True
        self.app.conf.geo_statistics_url = "http://eduid.docker"

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        mock_post = mocker.patch("requests.post")
        result = self._try_login()
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

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

    def test_geo_statistics_fail(self, mocker: MockerFixture) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # enable geo statistics
        self.app.conf.geo_statistics_feature_enabled = True
        self.app.conf.geo_statistics_url = "http://eduid.docker"

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        mock_post = mocker.patch("requests.post")
        mock_post.side_effect = RequestException("Test Exception")
        result = self._try_login()
        assert mock_post.call_count == 1

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )


class IdPTestLoginAPIManagedAccounts(IdPAPITests):
    @pytest.fixture(autouse=True)
    def setup_managed_accounts(self, setup_api: None) -> None:
        self.test_eppn = "ma-12345678"
        managed_account = self._create_managed_account_user(eppn=self.test_eppn)
        self.default_user = TestUser(eppn=managed_account.eppn, password="secret")

    def _create_managed_account_user(self, eppn: str) -> ManagedAccount:
        """
        Create a managed account user with a password
        """
        managed_account = ManagedAccount(eppn=eppn, data_owner="test", expire_at=utc_now() + timedelta(hours=1))
        password = Password(
            credential_id=str(ObjectId("145645678901234567890456")),
            salt="$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$",
            created_by="test",
            created_ts=datetime.fromisoformat("2023-01-24T08:19:25"),
            is_generated=True,
        )
        managed_account.credentials.add(password)
        self.app.managed_account_db.save(managed_account)
        return managed_account

    def test_login_pwauth_wrong_password(self, mocker: MockerFixture) -> None:
        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=False)
        result = self._try_login()
        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.USERNAMEPWAUTH],
            sso_cookie_val=None,
            pwauth_result=PwAuthResult(payload={"message": IdPMsg.wrong_credentials.value}),
        )

    def test_login_pwauth_right_password(self, mocker: MockerFixture) -> None:
        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(
                payload={
                    "message": IdPMsg.finished.value,
                    "target": "https://sp.example.edu/saml2/acs/",
                    "parameters": {"RelayState": self.relay_state},
                }
            ),
        )

        attributes = self.get_attributes(result)

        assert "eduPersonPrincipalName" in attributes
        assert attributes["eduPersonPrincipalName"] == [f"{self.test_eppn}@{self.app.conf.default_eppn_scope}"]

    def test_ForceAuthn_with_existing_SSO_session(self, mocker: MockerFixture) -> None:
        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login()

        assert result.finished_result is not None
        authn_response = self.parse_saml_authn_response(result.finished_result)
        session_info = authn_response.session_info()
        attributes: dict[str, list[Any]] = session_info["ava"]

        assert "eduPersonPrincipalName" in attributes
        assert attributes["eduPersonPrincipalName"] == [f"{self.test_eppn}@{self.app.conf.default_eppn_scope}"]

        # Log in again, with ForceAuthn="true"
        result2 = self._try_login(force_authn=True, username=False)

        assert result2.finished_result is not None
        authn_response2 = self.parse_saml_authn_response(result2.finished_result)
        # Make sure the second response isn't referring to the first login request
        assert authn_response.in_response_to != authn_response2.in_response_to

    def test_terminated_user(self, mocker: MockerFixture) -> None:
        user = self.app.managed_account_db.get_user_by_eppn(self.default_user.eppn)
        user.terminated = datetime.fromisoformat("2023-01-15T15:52:59.745")
        self.app.managed_account_db.save(user)

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH],
            error={"payload": {"message": IdPMsg.user_terminated.value}},
        )

    def test_with_unknown_sp(self, mocker: MockerFixture) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="UNKNOWN_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH],
            error={"status_code": 400, "status": "400 BAD REQUEST", "message": "SAML error: Unknown Service Provider"},
        )

    def test_sso_to_unknown_sp(self, mocker: MockerFixture) -> None:
        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login()

        assert result.visit_order == [IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED]

        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="UNKNOWN_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # Don't patch VCCS here to ensure a SSO is done, not a password authentication
        result2 = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result2,
            visit_order=[],
            sso_cookie_val=None,
            error={"status_code": 400, "status": "400 BAD REQUEST", "message": "SAML error: Unknown Service Provider"},
        )

    def test_eduperson_targeted_id(self, mocker: MockerFixture) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="COCO_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)
        assert "eduPersonTargetedID" in attributes
        assert attributes["eduPersonTargetedID"] == ["f0e831c0fcc8d61aef72e92f34e51f415f101050b8291a8c2c41ab4978b18f93"]

    def test_pairwise_id(self, mocker: MockerFixture) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="COCO_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)
        assert attributes["pairwise-id"] == [
            "133d9ecc64c5d8ed99ef00329e87b8677e74fc573e3f41ba0c259695813b9c19@test.scope"
        ]

    def test_subject_id(self, mocker: MockerFixture) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)
        assert attributes["subject-id"] == [f"{self.test_eppn}@test.scope"]

    def test_successful_authentication_alternative_acs(self, mocker: MockerFixture) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(assertion_consumer_service_url="https://localhost:8080/acs/")

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"target": "https://localhost:8080/acs/"}),
        )

    def test_geo_statistics_success(self, mocker: MockerFixture) -> None:
        # enable geo statistics
        self.app.conf.geo_statistics_feature_enabled = True
        self.app.conf.geo_statistics_url = "http://eduid.docker"

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        mock_post = mocker.patch("requests.post")
        result = self._try_login()
        assert mock_post.call_count == 1
        assert mock_post.call_args.kwargs.get("json") == {
            "data": {
                "user_id": "9e46df8e2f30d3f045b157741a1387ecfcbc840920d5a8386a8fd04c11ed7028",
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

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

    def test_geo_statistics_fail(self, mocker: MockerFixture) -> None:
        # enable geo statistics
        self.app.conf.geo_statistics_feature_enabled = True
        self.app.conf.geo_statistics_url = "http://eduid.docker"

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        mock_post = mocker.patch("requests.post")
        mock_post.side_effect = RequestException("Test Exception")
        result = self._try_login()
        assert mock_post.call_count == 1

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.USERNAMEPWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

    def test_assurance_failure_unknown_authn_context(self, mocker: MockerFixture) -> None:
        """
        Test that requesting an unknown authn context class returns a SAML error response.

        This tests the code path in next.py that handles IdPMsg.assurance_failure for SAML requests,
        returning an AuthnContextClassNotSupported SAML error to the SP.
        """
        self.add_test_user_tou()

        # Request an unknown authn context class - this should trigger assurance_failure
        authn_context = {
            "authn_context_class_ref": ["urn:no-such-class"],
            "comparison": "exact",
        }

        # Patch the VCCSClient so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)
        result = self._try_login(authn_context=authn_context)

        # The login should complete with a FINISHED action (containing SAML error response)
        assert result.finished_result is not None, f"Expected finished_result but got {result}"
        assert result.finished_result.payload.get("action") == IdPAction.FINISHED.value

        # The SAML response should contain an error - parse it to verify
        saml_response_b64 = result.finished_result.payload.get("parameters", {}).get("SAMLResponse")
        assert saml_response_b64 is not None, "Expected SAMLResponse in payload"

        # Decode and check it contains the expected error status and message
        import base64

        saml_response_xml = base64.b64decode(saml_response_b64).decode("utf-8")
        # Verify it's an error response with the authn context not supported message
        assert "status:AuthnFailed" in saml_response_xml, "Expected AuthnFailed status in SAML response"
        assert "Authentication context class not supported" in saml_response_xml, (
            "Expected 'Authentication context class not supported' message in SAML response"
        )

    def test_unsupported_binding(self, mocker: MockerFixture) -> None:
        """
        Test that requesting an unsupported response binding returns an error.

        This tests the code path when pysaml2 cannot find a supported binding for the SP.
        """
        import json
        import zlib
        from base64 import b64encode
        from http import HTTPStatus
        from urllib.parse import urlencode

        import saml2.time_util

        self.add_test_user_tou()

        # Create a SAML AuthnRequest with an unsupported ProtocolBinding
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<ns0:AuthnRequest xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"
        AssertionConsumerServiceURL="https://sp.example.edu/saml2/acs/"
        Destination="https://unittest-idp.example.edu/sso/redirect"
        ID="id-unsupported-binding-test"
        IssueInstant="{saml2.time_util.instant()}"
        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
        Version="2.0">
  <ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://sp.example.edu/saml2/metadata/</ns1:Issuer>
  <ns0:NameIDPolicy AllowCreate="false" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>
</ns0:AuthnRequest>"""

        # Encode for HTTP-Redirect binding (deflate + base64)
        compressed = zlib.compress(xml.encode("utf-8"))[2:-4]  # Strip zlib header and checksum
        saml_request = b64encode(compressed).decode("ascii")

        # Send the SAML request to the SSO redirect endpoint
        query_string = urlencode({"SAMLRequest": saml_request, "RelayState": "test-relay-state"})

        # Patch the VCCSClient, so we do not need a vccs server
        mocker.patch.object(VCCSClient, "authenticate", return_value=True)

        with self.session_cookie_anon(self.browser) as client:
            # First, send the SAML request
            response = client.get(f"/sso/redirect?{query_string}")
            assert response.status_code == HTTPStatus.FOUND, f"Expected redirect, got {response.status_code}"

            # Extract the login ref from the redirect URL
            redirect_loc = response.headers.get("Location", "")
            ref = redirect_loc.split("/")[-1]

            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()

            # Call next to get to the password auth step
            data = json.dumps({"ref": ref, "csrf_token": csrf_token})
            next_response = client.post("/next", data=data, content_type=self.content_type_json)
            assert next_response.status_code == HTTPStatus.OK

            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()

            # Now do password auth
            data = json.dumps(
                {
                    "ref": ref,
                    "username": self.test_user.eppn,
                    "password": "bar",
                    "csrf_token": csrf_token,
                }
            )
            pw_response = client.post("/pw_auth", data=data, content_type=self.content_type_json)
            assert pw_response.status_code == HTTPStatus.OK

            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()

            # Call next again - this should trigger the unsupported binding error
            # The SAMLError is now caught and converted to a BadRequest
            data = json.dumps({"ref": ref, "csrf_token": csrf_token})
            final_response = client.post("/next", data=data, content_type=self.content_type_json)

        # The response should be a BadRequest error about the unsupported binding
        assert final_response.status_code == HTTPStatus.BAD_REQUEST, (
            f"Expected 400 Bad Request, got {final_response.status_code}: {final_response.data}"
        )
        response_text = final_response.data.decode("utf-8")
        # The error is rendered as an HTML error page
        assert "Bad Request" in response_text, f"Expected 'Bad Request' in response: {response_text}"
        assert "login request could not be processed" in response_text, (
            f"Expected error message in response: {response_text}"
        )


class IdPTestNewSignup(IdPAPITests):
    """Tests for the /signup_auth endpoint and its integration with /next."""

    @pytest.fixture(scope="class")
    def update_config(self) -> dict[str, Any]:
        config = self._get_base_config()
        config["allow_new_signup_logins"] = True
        return config

    def _get_ref(
        self,
        force_authn: bool = False,
        authn_context: dict[str, Any] | None = None,
    ) -> str:
        """Create a SAML AuthnRequest and return the login ref."""
        _ref_result = self._get_login_ref(
            device=self.browser,
            saml2_client=self.saml2_client,
            authn_context=authn_context,
            force_authn=force_authn,
            assertion_consumer_service_url=None,
        )
        assert not isinstance(_ref_result, LoginResultAPI), f"Failed to get login ref: {_ref_result}"
        ref, _resp = _ref_result
        return ref

    def _setup_signup_session(
        self,
        client: CSRFTestClient,
        ref: str,
        eppn: str,
        user_created_at: datetime | None = None,
        idp_request_ref: str | None = None,
        login_source: LoginApplication | None = LoginApplication.signup,
    ) -> None:
        """Set signup session state on the client session."""
        if user_created_at is None:
            user_created_at = utc_now()
        if idp_request_ref is None:
            idp_request_ref = ref

        with client.session_transaction() as sess:
            sess.signup.user_created = True
            sess.signup.user_created_at = user_created_at
            if idp_request_ref is not None:
                sess.signup.idp_request_ref = RequestRef(idp_request_ref)
            sess.common.eppn = eppn
            if login_source is not None:
                sess.common.login_source = login_source

    def _call_signup_auth(self, client: CSRFTestClient, ref: str) -> NextResult:
        """Call /signup_auth with the given ref."""
        with self.app.test_request_context():
            with client.session_transaction() as sess:
                data = {"ref": ref, "csrf_token": sess.get_csrf_token()}
            response = client.post("/signup_auth", data=json.dumps(data), content_type=self.content_type_json)

        logger.debug(f"signup_auth returned:\n{json.dumps(response.json, indent=4)}")
        if response.is_json:
            assert response.json is not None
            if response.json.get("error"):
                return NextResult(payload=self.get_response_payload(response), error=response.json)
        return NextResult(payload=self.get_response_payload(response))

    def _call_next(self, device: CSRFTestClient, ref: str) -> NextResult:
        """Call /next with the given ref."""
        with self.app.test_request_context():
            with device.session_transaction() as sess:
                data = {"ref": ref, "csrf_token": sess.get_csrf_token()}
            response = device.post("/next", data=json.dumps(data), content_type=self.content_type_json)

        logger.debug(f"Next endpoint returned:\n{json.dumps(response.json, indent=4)}")
        if response.is_json:
            assert response.json is not None
            if response.json.get("error"):
                return NextResult(payload=self.get_response_payload(response), error=response.json)
        return NextResult(payload=self.get_response_payload(response))

    def test_new_signup_accepted(self) -> None:
        """signup_auth creates SSO session, then /next returns SAML response."""
        self.add_test_user_tou()
        ref = self._get_ref()

        with self.session_cookie_anon(self.browser) as client:
            self._setup_signup_session(client, ref=ref, eppn=self.test_user.eppn)

            # Step 1: /signup_auth creates SSO session + sets cookie
            auth_result = self._call_signup_auth(client, ref)
            assert auth_result.error is None, f"signup_auth error: {auth_result.error}"
            assert auth_result.payload.get("finished") is True

            # Step 2: /next finds SSO session and returns SAML response
            next_result = self._call_next(client, ref)
            assert next_result.error is None, f"next error: {next_result.error}"
            assert next_result.payload.get("action") == IdPAction.FINISHED.value
            assert "SAMLResponse" in next_result.payload.get("parameters", {})

    def test_new_signup_expired(self) -> None:
        """Signup that is too old should be rejected by /signup_auth."""
        self.add_test_user_tou()
        ref = self._get_ref()

        with self.session_cookie_anon(self.browser) as client:
            self._setup_signup_session(
                client, ref=ref, eppn=self.test_user.eppn, user_created_at=utc_now() - timedelta(minutes=10)
            )
            auth_result = self._call_signup_auth(client, ref)
            assert auth_result.error is not None

    def test_new_signup_force_authn(self) -> None:
        """ForceAuthn should cause /signup_auth to reject."""
        self.add_test_user_tou()
        ref = self._get_ref(force_authn=True)

        with self.session_cookie_anon(self.browser) as client:
            self._setup_signup_session(client, ref=ref, eppn=self.test_user.eppn)
            auth_result = self._call_signup_auth(client, ref)
            assert auth_result.error is not None

    def test_new_signup_wrong_ref(self) -> None:
        """Mismatched idp_request_ref should cause /signup_auth to reject."""
        self.add_test_user_tou()
        ref = self._get_ref()

        with self.session_cookie_anon(self.browser) as client:
            self._setup_signup_session(client, ref=ref, eppn=self.test_user.eppn, idp_request_ref="wrong-ref")
            auth_result = self._call_signup_auth(client, ref)
            assert auth_result.error is not None

    def test_new_signup_no_login_source(self) -> None:
        """Without login_source=signup, /signup_auth should reject."""
        self.add_test_user_tou()
        ref = self._get_ref()

        with self.session_cookie_anon(self.browser) as client:
            self._setup_signup_session(client, ref=ref, eppn=self.test_user.eppn, login_source=None)
            auth_result = self._call_signup_auth(client, ref)
            assert auth_result.error is not None
