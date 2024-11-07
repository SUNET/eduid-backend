import logging
import os
from datetime import datetime, timedelta
from typing import Any, cast
from unittest.mock import MagicMock, patch

from bson import ObjectId
from pydantic import parse_obj_as
from requests import RequestException
from saml2.client import Saml2Client

from eduid.common.misc.timeutil import utc_now
from eduid.common.models.generic import HttpUrlStr
from eduid.common.models.saml2 import EduidAuthnContextClass
from eduid.userdb import MailAddress
from eduid.userdb.credentials import Password
from eduid.userdb.maccapi.userdb import ManagedAccount
from eduid.userdb.mail import MailAddressList
from eduid.vccs.client import VCCSClient
from eduid.webapp.common.api.testing import CSRFTestClient
from eduid.webapp.common.authn.utils import get_saml2_config
from eduid.webapp.idp.helpers import IdPAction, IdPMsg
from eduid.webapp.idp.other_device.data import OtherDeviceState
from eduid.webapp.idp.tests.test_api import FinishedResultAPI, IdPAPITests, PwAuthResult, TestUser
from eduid.workers.am import AmCelerySingleton

logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


class IdPTestLoginAPI(IdPAPITests):
    def test_login_start(self) -> None:
        result = self._try_login(test_user=TestUser(eppn=None, password=None))

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH],
            sso_cookie_val=None,
        )

    def test_login_pwauth_wrong_password(self) -> None:
        result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.PWAUTH],
            sso_cookie_val=None,
            pwauth_result=PwAuthResult(
                payload={
                    "message": IdPMsg.wrong_credentials.value,
                }
            ),
        )

    def test_login_pwauth_right_password(self) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
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

    def test_login_pwauth_right_password_and_tou_acceptance(self) -> None:
        # Enable AM sync of user to central db for this particular test
        AmCelerySingleton.worker_config.mongo_uri = self.app.conf.mongo_uri

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.TOU, IdPAction.FINISHED],
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

    def test_login_mfaauth(self) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # add security key to user
        self.add_test_user_security_key()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[
                IdPAction.PWAUTH,
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

    def test_login_no_mandatory_mfa(self) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # add security key to user
        self.add_test_user_security_key(always_use_security_key_user_preference=False)

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[
                IdPAction.PWAUTH,
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

    def test_login_no_mandatory_mfa_with_mfa_accr(self) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # add security key to user
        self.add_test_user_security_key(always_use_security_key_user_preference=False)

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(
                authn_context={
                    "authn_context_class_ref": [EduidAuthnContextClass.REFEDS_MFA.value],
                    "comparison": "exact",
                }
            )
        self._check_login_result(
            result=result,
            visit_order=[
                IdPAction.PWAUTH,
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

    def test_login_missing_attributes(self) -> None:
        # pre-accept ToU for this test
        user, _ = self.add_test_user_tou()

        # remove mail address from user to simulate missing attribute
        user.mail_addresses = MailAddressList()
        self.request_user_sync(user)

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
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

    def test_ForceAuthn_with_existing_SSO_session(self) -> None:
        # add security key to user
        self.add_test_user_security_key()

        for accr in [None, EduidAuthnContextClass.PASSWORD_PT, EduidAuthnContextClass.REFEDS_MFA]:
            requested_authn_context = None
            if accr is not None:
                requested_authn_context = {"authn_context_class_ref": [accr.value]}

            # pre-accept ToU for this test
            self.add_test_user_tou()

            # Patch the VCCSClient, so we do not need a vccs server
            with patch.object(VCCSClient, "authenticate") as mock_vccs:
                mock_vccs.return_value = True
                result = self._try_login()

            assert result.finished_result is not None
            authn_response = self.parse_saml_authn_response(result.finished_result)
            session_info = authn_response.session_info()
            attributes: dict[str, list[Any]] = session_info["ava"]

            assert "eduPersonPrincipalName" in attributes
            assert attributes["eduPersonPrincipalName"] == [f"hubba-bubba@{self.app.conf.default_eppn_scope}"]

            # Log in again, with ForceAuthn="true"
            # Patch the VCCSClient, so we do not need a vccs server
            with patch.object(VCCSClient, "authenticate") as mock_vccs:
                mock_vccs.return_value = True
                result2 = self._try_login(
                    force_authn=True, authn_context=requested_authn_context, sso_cookie_val=result.sso_cookie_val
                )

            if accr is EduidAuthnContextClass.REFEDS_MFA:
                assert result2.visit_order == [
                    IdPAction.PWAUTH,
                    IdPAction.MFA,
                    IdPAction.FINISHED,
                ], f"Actual visit order: {result2.visit_order}"
            else:
                assert result2.finished_result is not None
                authn_response2 = self.parse_saml_authn_response(result2.finished_result)
                # Make sure the second response isn't referring to the first login request
                assert authn_response.in_response_to != authn_response2.in_response_to

    def test_login_other_device(self) -> None:
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
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            device_2_result2 = self._try_login(device=device2, login_ref=login_ref)

        self._check_login_result(
            result=device_2_result2,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
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

    def test_login_other_device_with_accr(self) -> None:
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
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            device_2_result2 = self._try_login(device=device2, login_ref=login_ref)

        self._check_login_result(
            result=device_2_result2,
            visit_order=[IdPAction.PWAUTH, IdPAction.MFA, IdPAction.FINISHED],
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

    def test_terminated_user(self) -> None:
        user = self.amdb.get_user_by_eppn(self.test_user.eppn)
        user.terminated = datetime.fromisoformat("2020-02-25T15:52:59.745")
        self.amdb.save(user)

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH],
            error={"payload": {"message": IdPMsg.user_terminated.value}},
        )

    def test_with_unknown_sp(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="UNKNOWN_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH],
            error={"status_code": 400, "status": "400 BAD REQUEST", "message": "SAML error: Unknown Service Provider"},
        )

    def test_sso_to_unknown_sp(self) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
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

    def test_eduperson_targeted_id(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="COCO_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)
        assert "eduPersonTargetedID" in attributes
        assert attributes["eduPersonTargetedID"] == ["71a13b105e83aa69c31f41b08ea83694e0fae5f368d17ef18ba59e0f9e407ec9"]

    def test_schac_personal_unique_code_esi(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="ESI_COCO_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
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

    def test_pairwise_id(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="COCO_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)

        assert attributes["pairwise-id"] == [
            "36382d115a9b7d8c27cc9eed94aab0ea6cc16a8becc5a468922e36e5a351f8f9@test.scope"
        ]

    def test_subject_id(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)
        assert attributes["subject-id"] == ["hubba-bubba@test.scope"]

    def test_mail_local_address(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # add another mail address to the test user
        self.add_test_user_mail_address(MailAddress(email="test@example.com", is_verified=True))

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)

        assert attributes["mailLocalAddress"] == ["johnsmith@example.com", "test@example.com"]

    def test_successful_authentication_alternative_acs(self) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(assertion_consumer_service_url="https://localhost:8080/acs/")

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"target": "https://localhost:8080/acs/"}),
        )

    def test_geo_statistics_success(self) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # enable geo statistics
        self.app.conf.geo_statistics_feature_enabled = True
        self.app.conf.geo_statistics_url = parse_obj_as(HttpUrlStr, "http://eduid.docker")

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            with patch("requests.post", new_callable=MagicMock) as mock_post:
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
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

    def test_geo_statistics_fail(self) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # enable geo statistics
        self.app.conf.geo_statistics_feature_enabled = True
        self.app.conf.geo_statistics_url = parse_obj_as(HttpUrlStr, "http://eduid.docker")

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            with patch("requests.post", new_callable=MagicMock) as mock_post:
                mock_post.side_effect = RequestException("Test Exception")
                result = self._try_login()
                assert mock_post.call_count == 1

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )


class IdPTestLoginAPIManagedAccounts(IdPAPITests):
    def setUp(self, *args: Any, **kwargs: Any) -> None:
        super().setUp(*args, **kwargs)
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

    def test_login_pwauth_wrong_password(self) -> None:
        result = self._try_login()
        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.PWAUTH],
            sso_cookie_val=None,
            pwauth_result=PwAuthResult(payload={"message": IdPMsg.wrong_credentials.value}),
        )

    def test_login_pwauth_right_password(self) -> None:
        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
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

    def test_ForceAuthn_with_existing_SSO_session(self) -> None:
        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        assert result.finished_result is not None
        authn_response = self.parse_saml_authn_response(result.finished_result)
        session_info = authn_response.session_info()
        attributes: dict[str, list[Any]] = session_info["ava"]

        assert "eduPersonPrincipalName" in attributes
        assert attributes["eduPersonPrincipalName"] == [f"{self.test_eppn}@{self.app.conf.default_eppn_scope}"]

        # Log in again, with ForceAuthn="true"
        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result2 = self._try_login(force_authn=True)

        assert result2.finished_result is not None
        authn_response2 = self.parse_saml_authn_response(result2.finished_result)
        # Make sure the second response isn't referring to the first login request
        assert authn_response.in_response_to != authn_response2.in_response_to

    def test_terminated_user(self) -> None:
        user = self.app.managed_account_db.get_user_by_eppn(self.default_user.eppn)
        user.terminated = datetime.fromisoformat("2023-01-15T15:52:59.745")
        self.app.managed_account_db.save(user)

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        self._check_login_result(
            result=result, visit_order=[IdPAction.PWAUTH], error={"payload": {"message": IdPMsg.user_terminated.value}}
        )

    def test_with_unknown_sp(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="UNKNOWN_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH],
            error={"status_code": 400, "status": "400 BAD REQUEST", "message": "SAML error: Unknown Service Provider"},
        )

    def test_sso_to_unknown_sp(self) -> None:
        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login()

        assert result.visit_order == [IdPAction.PWAUTH, IdPAction.FINISHED]

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

    def test_eduperson_targeted_id(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="COCO_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)
        assert "eduPersonTargetedID" in attributes
        assert attributes["eduPersonTargetedID"] == ["f0e831c0fcc8d61aef72e92f34e51f415f101050b8291a8c2c41ab4978b18f93"]

    def test_pairwise_id(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="COCO_SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)
        assert attributes["pairwise-id"] == [
            "133d9ecc64c5d8ed99ef00329e87b8677e74fc573e3f41ba0c259695813b9c19@test.scope"
        ]

    def test_subject_id(self) -> None:
        sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="SP_CONFIG")
        saml2_client = Saml2Client(config=sp_config)

        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(saml2_client=saml2_client)

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

        attributes = self.get_attributes(result, saml2_client=saml2_client)
        assert attributes["subject-id"] == [f"{self.test_eppn}@test.scope"]

    def test_successful_authentication_alternative_acs(self) -> None:
        # pre-accept ToU for this test
        self.add_test_user_tou()

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            result = self._try_login(assertion_consumer_service_url="https://localhost:8080/acs/")

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"target": "https://localhost:8080/acs/"}),
        )

    def test_geo_statistics_success(self) -> None:
        # enable geo statistics
        self.app.conf.geo_statistics_feature_enabled = True
        self.app.conf.geo_statistics_url = parse_obj_as(HttpUrlStr, "http://eduid.docker")

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            with patch("requests.post", new_callable=MagicMock) as mock_post:
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
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )

    def test_geo_statistics_fail(self) -> None:
        # enable geo statistics
        self.app.conf.geo_statistics_feature_enabled = True
        self.app.conf.geo_statistics_url = parse_obj_as(HttpUrlStr, "http://eduid.docker")

        # Patch the VCCSClient, so we do not need a vccs server
        with patch.object(VCCSClient, "authenticate") as mock_vccs:
            mock_vccs.return_value = True
            with patch("requests.post", new_callable=MagicMock) as mock_post:
                mock_post.side_effect = RequestException("Test Exception")
                result = self._try_login()
                assert mock_post.call_count == 1

        self._check_login_result(
            result=result,
            visit_order=[IdPAction.PWAUTH, IdPAction.FINISHED],
            finish_result=FinishedResultAPI(payload={"message": IdPMsg.finished.value}),
        )
