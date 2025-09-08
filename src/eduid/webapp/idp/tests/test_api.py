import json
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any
from unittest.mock import MagicMock, patch

from bson import ObjectId
from fido2.webauthn import AuthenticatorAttachment
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.response import AuthnResponse
from werkzeug.test import TestResponse

from eduid.common.misc.timeutil import utc_now
from eduid.common.models.webauthn import WebauthnChallenge
from eduid.userdb import ToUEvent
from eduid.userdb.credentials import Credential, FidoCredential, Webauthn
from eduid.userdb.credentials.external import ExternalCredential, TrustFramework, external_credential_from_dict
from eduid.userdb.idp import IdPUser
from eduid.userdb.mail import MailAddress
from eduid.userdb.testing import SetupConfig
from eduid.userdb.user import User
from eduid.webapp.common.api.testing import CSRFTestClient, EduidAPITestCase
from eduid.webapp.common.authn.cache import IdentityCache, OutstandingQueriesCache, StateCache
from eduid.webapp.common.authn.utils import get_saml2_config
from eduid.webapp.common.session.namespaces import AuthnRequestRef, PySAML2Dicts
from eduid.webapp.idp.app import IdPApp, init_idp_app
from eduid.webapp.idp.helpers import IdPAction
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.sso_session import SSOSession, SSOSessionId
from eduid.webapp.idp.views.mfa_auth import CheckResult

__author__ = "ft"

logger = logging.getLogger(__name__)


@dataclass
class GenericResult:
    payload: dict[str, Any]


@dataclass
class NextResult(GenericResult):
    error: dict[str, Any] | None = None


@dataclass
class PwAuthResult(GenericResult):
    sso_cookie_val: SSOSessionId | None = None
    cookies: dict[str, Any] = field(default_factory=dict)


@dataclass
class OtherDevice1Result(PwAuthResult):
    pass


@dataclass
class OtherDevice2Result(PwAuthResult):
    pass


@dataclass
class TouResult(GenericResult):
    pass


@dataclass
class MfaResult(GenericResult):
    pass


@dataclass
class FinishedResultAPI(GenericResult):
    pass


@dataclass
class TestUser:
    eppn: str | None
    password: str | None


@dataclass
class LoginResultAPI:
    response: TestResponse | None = None
    ref: str | None = None
    sso_cookie_val: SSOSessionId | None = None
    visit_count: dict[str, int] = field(default_factory=dict)
    visit_order: list[IdPAction] = field(default_factory=list)
    pwauth_result: PwAuthResult | None = None
    tou_result: TouResult | None = None
    mfa_result: MfaResult | None = None
    other_device1_result: OtherDevice1Result | None = None
    finished_result: FinishedResultAPI | None = None
    error: dict[str, Any] | None = None


class IdPAPITests(EduidAPITestCase[IdPApp]):
    """Base TestCase for those tests that need a full environment setup"""

    default_user: TestUser

    def setUp(self, config: SetupConfig | None = None) -> None:
        super().setUp(config=config)
        self.idp_entity_id = "https://unittest-idp.example.edu/idp.xml"
        self.relay_state = AuthnRequestRef("test-fest")
        self.sp_config = get_saml2_config(self.app.conf.pysaml2_config, name="SP_CONFIG")
        # pysaml2 likes to keep state about ongoing logins, data from login to when you logout etc.
        self._pysaml2_caches = PySAML2Dicts({})
        self.pysaml2_state = StateCache(self._pysaml2_caches)  # _saml2_state in _pysaml2_caches
        self.pysaml2_identity = IdentityCache(self._pysaml2_caches)  # _saml2_identities in _pysaml2_caches
        self.pysaml2_oq = OutstandingQueriesCache(self._pysaml2_caches)  # _saml2_outstanding_queries in _pysaml2_caches
        self.saml2_client = Saml2Client(config=self.sp_config, identity_cache=self.pysaml2_identity)
        self.default_user = TestUser(eppn=self.test_user.eppn, password="bar")

    def load_app(self, config: Mapping[str, Any] | None) -> IdPApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_idp_app(test_config=config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config = super().update_config(config)
        fn = PurePath(__file__).with_name("data") / "test_SSO_conf.py"
        config.update(
            {
                "pysaml2_config": str(fn),
                "fticks_secret_key": "test test",
                "eduperson_targeted_id_secret_key": "eptid_secret",
                "pairwise_id_secret_key": "pairwise_secret",
                "sso_cookie": {"key": "test_sso_cookie"},
                "eduid_site_url": "https://eduid.docker_dev",
                "fido2_rp_id": "idp.example.com",
                "login_bundle_url": "https://idp.eduid.docker/test-bundle",
                "tou_version": "2016-v1",
                "default_eppn_scope": "test.scope",
                "allow_other_device_logins": True,
                "other_device_url": "http://test.localhost/login/other",
                "other_device_secret_key": "lx0sg0g21QUkiu9JAPfhx4hJ5prJtbk1PPE-OBvpiAk=",
                "known_devices_secret_key": "WwemHQgPm1hpx41NYaVBQpRV7BAq0OMtfF3k4H72J7c=",
                "geo_statistics_secret_key": "gk5cBWIZ6k-mNHWnA33ZpsgXfgH50Wi_s3mUNI9GF0o=",
                "logging_config": {
                    "loggers": {
                        "saml2": {"level": "INFO"},
                        "xmlsec": {"level": "INFO"},
                        "urllib3": {"level": "INFO"},
                        "pymongo.serverSelection": {"level": "INFO"},
                        "pymongo.connection": {"level": "INFO"},
                        "pymongo.command": {"level": "INFO"},
                        "pymongo.topology": {"level": "INFO"},
                    }
                },
            }
        )
        return config

    @staticmethod
    def get_cookie_val(cookie_name: str, cookies: str | None) -> str | None:
        """
        Get the value of a cookie.
        """
        if cookies is None:
            return None

        _re = f".*{cookie_name}=(.+?);.*"
        _sso_cookie_re = re.match(_re, cookies)
        if _sso_cookie_re:
            return _sso_cookie_re.groups()[0]
        return None

    def _try_login(
        self,
        saml2_client: Saml2Client | None = None,
        authn_context: Mapping[str, Any] | None = None,
        force_authn: bool = False,
        assertion_consumer_service_url: str | None = None,
        test_user: TestUser | None = None,
        username: str | bool | None = None,
        sso_cookie_val: str | None = None,
        session_cookie_val: str | None = None,
        mfa_credential: Credential | None = None,
        other_device: bool = False,
        device: CSRFTestClient | None = None,
        login_ref: str | None = None,
    ) -> LoginResultAPI:
        """
        Try logging in to the IdP.

        :return: Information about how far we got (reached LoginState) and the last response instance.
        """
        user: TestUser = test_user if test_user is not None else self.default_user

        _saml2_client = saml2_client if saml2_client is not None else self.saml2_client

        if device is None:
            device = self.browser

        with self.session_cookie_anon(device) as browser:
            ref = login_ref
            resp = None
            if login_ref is None:
                # create SAML request
                session_id: str
                info: Mapping[str, Any]
                (session_id, info) = _saml2_client.prepare_for_authenticate(
                    entityid=self.idp_entity_id,
                    relay_state=self.relay_state,
                    binding=BINDING_HTTP_REDIRECT,
                    requested_authn_context=authn_context,
                    force_authn=force_authn,
                    assertion_consumer_service_url=assertion_consumer_service_url,
                )
                self.pysaml2_oq.set(session_id, self.relay_state)

                # Send SAML request to SAML endpoint, expect a redirect to the login bundle back
                path = self._extract_path_from_info(info)
                resp = browser.get(path)
                if resp.status_code != 302:
                    return LoginResultAPI(response=resp)

                redirect_loc = self._extract_path_from_response(resp)
                ref = redirect_loc.split("/")[-1]

            result = LoginResultAPI(ref=ref, response=resp)
            cookie_jar = {}
            if sso_cookie_val is not None:
                cookie_jar["idpauthn"] = sso_cookie_val
            if session_cookie_val is not None:
                cookie_jar["sessid"] = session_cookie_val

            assert ref is not None, "Login ref needs to be set by this point"

            while True:
                logger.info(f"Main API test loop, current state: {result}")

                # Call the 'next' endpoint
                _next = self._call_next(device, ref)

                if _next.error:
                    result.error = _next.error
                    return result

                _action = IdPAction(_next.payload["action"])
                if _action not in result.visit_count:
                    result.visit_count[_action] = 0
                result.visit_count[_action] += 1
                result.visit_order += [_action]

                if result.visit_count[_action] > 1:
                    # break on re-visiting a previous state
                    logger.error(f"Next state {_action} already visited, aborting with result {result}")
                    return result

                match _action:
                    case IdPAction.USERNAMEPWAUTH | IdPAction.PWAUTH:
                        if other_device:
                            result.other_device1_result = self._call_other_device1(
                                device, target="http://test.localhost/use_other_1", ref=ref
                            )
                            return result

                        if username is None:
                            username = user.eppn

                        if username is False and user.password:
                            # make the call to pwauth without username
                            result.pwauth_result = self._call_pwauth(
                                device=device, target=_next.payload["target"], ref=ref, password=user.password
                            )
                        elif not username or not user.password:
                            logger.error(f"Can't login without username and password, aborting with result {result}")
                            return result
                        else:
                            result.pwauth_result = self._call_pwauth(
                                device=device,
                                target=_next.payload["target"],
                                ref=ref,
                                username=user.eppn,
                                password=user.password,
                            )
                        result.sso_cookie_val = result.pwauth_result.sso_cookie_val
                        cookie_jar.update(result.pwauth_result.cookies)

                    case IdPAction.MFA:
                        if mfa_credential is None:
                            assert user.eppn is not None  # please mypy
                            _user = self.app.userdb.lookup_user(user.eppn)
                            assert _user is not None
                            # default mfa_credential to the first FidoCredential on the user
                            try:
                                mfa_credential = _user.credentials.filter(FidoCredential)[0]
                            except IndexError:
                                raise AssertionError(
                                    f"No FidoCredential found for user {_user.eppn}, aborting with result {result}"
                                )

                        result.mfa_result = self._call_mfa(device, _next.payload["target"], ref, mfa_credential)

                    case IdPAction.TOU:
                        result.tou_result = self._call_tou(
                            device, _next.payload["target"], ref, user_accepts=self.app.conf.tou_version
                        )

                    case IdPAction.FINISHED:
                        result.finished_result = FinishedResultAPI(payload=_next.payload)
                        return result

                    case _ as failed_action:
                        raise AssertionError(f"Unexpected action: {failed_action} - result {result}")

    def _call_next(self, device: CSRFTestClient, ref: str) -> NextResult:
        with self.session_cookie_anon(device) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"ref": ref, "csrf_token": sess.get_csrf_token()}
                response = client.post("/next", data=json.dumps(data), content_type=self.content_type_json)
        logger.debug(f"Next endpoint returned:\n{json.dumps(response.json, indent=4)}")
        if response.is_json:
            assert response.json is not None
            if response.json.get("error"):
                return NextResult(payload=self.get_response_payload(response), error=response.json)
        if response._status_code != 200 and response._status_code != 302:
            _page_text = response.data.decode("UTF-8")
            _re = r"<p>(.*?error:.*?)</p>"
            _re_match = re.search(_re, _page_text)
            assert _re_match is not None
            _error_message = _re_match.group(1)
            _error: dict[str, Any] = {
                "status_code": response._status_code,
                "status": response.status,
                "message": _error_message,
            }
            return NextResult(payload={}, error=_error)
        return NextResult(payload=self.get_response_payload(response))

    def _call_pwauth(
        self, device: CSRFTestClient, target: str, ref: str, username: str | None = None, password: str | None = None
    ) -> PwAuthResult:
        assert password is not None, "password is required for _call_pwauth"
        with self.session_cookie_anon(device) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"ref": ref, "password": password, "csrf_token": sess.get_csrf_token()}
                    if username:
                        data["username"] = username
                response = client.post(target, data=json.dumps(data), content_type=self.content_type_json)
        logger.debug(f"PwAuth endpoint returned:\n{json.dumps(response.json, indent=4)}")
        result = PwAuthResult(payload=self.get_response_payload(response))
        cookies = response.headers.get("Set-Cookie")
        if not cookies:
            return result

        # Save the SSO cookie value
        sso_cookie_val = self.get_cookie_val(cookie_name=self.app.conf.sso_cookie.key, cookies=cookies)
        if sso_cookie_val:
            result.sso_cookie_val = SSOSessionId(sso_cookie_val)

        if result.sso_cookie_val:
            result.cookies = {self.app.conf.sso_cookie.key: result.sso_cookie_val}

        return result

    def _call_tou(self, device: CSRFTestClient, target: str, ref: str, user_accepts: str | None) -> TouResult:
        with self.session_cookie_anon(device) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"ref": ref, "csrf_token": sess.get_csrf_token()}
                    if user_accepts:
                        data["user_accepts"] = user_accepts
                response = client.post(target, data=json.dumps(data), content_type=self.content_type_json)
        logger.debug(f"ToU endpoint returned:\n{json.dumps(response.json, indent=4)}")
        result = TouResult(payload=self.get_response_payload(response))
        return result

    @patch("eduid.webapp.idp.views.mfa_auth._check_webauthn")
    @patch("eduid.webapp.common.authn.fido_tokens.start_token_verification")
    def _call_mfa(
        self,
        device: CSRFTestClient,
        target: str,
        ref: str,
        mfa_credential: Credential,
        mock_stv: MagicMock,
        mock_cw: MagicMock,
    ) -> MfaResult:
        mock_stv.return_value = WebauthnChallenge(webauthn_options={"mock_webautn_options": "mock_webauthn_options"})
        mock_cw.return_value = None
        # first call to mfa endpoint returns a challenge
        with self.session_cookie_anon(device) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"ref": ref, "csrf_token": sess.get_csrf_token()}
                response = client.post(target, json=data)

        payload = self.get_response_payload(response=response)
        assert payload.get("webauthn_options") == mock_stv.return_value.webauthn_options, (
            f"webauthn_options: {payload.get('webauthn_options')}, Expected: {mock_stv.return_value.webauthn_options}"
        )
        assert not payload.get("finished"), "Expected finished=False"

        logger.debug(f"MFA endpoint returned (challenge):\n{json.dumps(response.json, indent=4)}")

        # mock valid mfa auth
        mock_cw.return_value = CheckResult(
            credential=mfa_credential, authn_data=AuthnData(cred_id=mfa_credential.key, timestamp=utc_now())
        )
        # second call to mfa endpoint returns a result
        with self.session_cookie_anon(device) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"ref": ref, "csrf_token": sess.get_csrf_token()}
                response = client.post(target, json=data)

        result = MfaResult(payload=self.get_response_payload(response))
        return result

    def _call_other_device1(
        self, device: CSRFTestClient, target: str, ref: str, response_code: str | None = None
    ) -> OtherDevice1Result:
        with self.session_cookie_anon(device) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"ref": ref, "csrf_token": sess.get_csrf_token()}
                    if response_code is not None:
                        data["action"] = "SUBMIT_CODE"
                        data["response_code"] = response_code
                response = client.post(target, data=json.dumps(data), content_type=self.content_type_json)
        logger.debug(f"Other device1 endpoint returned:\n{json.dumps(response.json, indent=4)}")
        result = OtherDevice1Result(payload=self.get_response_payload(response))
        session_cookie_val = self.get_cookie_val(
            cookie_name=self.app.conf.flask.session_cookie_name, cookies=response.headers.get("Set-Cookie")
        )
        result.cookies = {self.app.conf.flask.session_cookie_name: session_cookie_val}
        if not result.cookies:
            return result

        # Save the SSO cookie value
        sso_cookie_val = self.get_cookie_val(
            cookie_name=self.app.conf.sso_cookie.key, cookies=response.headers.get("Set-Cookie")
        )
        if sso_cookie_val:
            result.sso_cookie_val = SSOSessionId(sso_cookie_val)

        if result.sso_cookie_val:
            result.cookies.update({self.app.conf.sso_cookie.key: result.sso_cookie_val})

        return result

    def _call_other_device2(
        self,
        device: CSRFTestClient,
        target: str,
        state_id: str,
    ) -> OtherDevice2Result:
        with self.session_cookie_anon(device) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"state_id": state_id, "csrf_token": sess.get_csrf_token()}
                response = client.post(target, data=json.dumps(data), content_type=self.content_type_json)
        logger.debug(f"Other device2 endpoint returned:\n{json.dumps(response.json, indent=4)}")
        result = OtherDevice2Result(payload=self.get_response_payload(response))
        session_cookie_val = self.get_cookie_val(
            cookie_name=self.app.conf.flask.session_cookie_name, cookies=response.headers.get("Set-Cookie")
        )
        result.cookies = {self.app.conf.flask.session_cookie_name: session_cookie_val}

        # Save the SSO cookie value
        sso_cookie_val = self.get_cookie_val(
            cookie_name=self.app.conf.sso_cookie.key, cookies=response.headers.get("Set-Cookie")
        )
        if sso_cookie_val:
            result.sso_cookie_val = SSOSessionId(sso_cookie_val)

        if result.sso_cookie_val:
            result.cookies.update({self.app.conf.sso_cookie.key: result.sso_cookie_val})

        return result

    def _extract_path_from_response(self, response: TestResponse) -> str:
        return self._extract_path_from_info({"headers": response.headers})

    def _extract_path_from_info(self, info: Mapping[str, Any]) -> str:
        _location_headers = [_hdr for _hdr in info["headers"] if _hdr[0] == "Location"]
        # get first Location URL
        loc = _location_headers[0][1]
        return self._extract_path_from_url(loc)

    def _extract_path_from_url(self, url: str) -> str:
        # It is a complete URL, extract the path from it (8 is to skip over slashes in https://)
        _idx = url[8:].index("/")
        path = url[8 + _idx :]
        return path

    def parse_saml_authn_response(
        self, result: FinishedResultAPI, saml2_client: Saml2Client | None = None
    ) -> AuthnResponse:
        _saml2_client = saml2_client if saml2_client is not None else self.saml2_client

        xmlstr = result.payload["parameters"]["SAMLResponse"]
        outstanding_queries = self.pysaml2_oq.outstanding_queries()
        return _saml2_client.parse_authn_request_response(xmlstr, BINDING_HTTP_POST, outstanding_queries)

    def get_sso_session(self, sso_cookie_val: str) -> SSOSession | None:
        if sso_cookie_val is None:
            return None
        return self.app.sso_sessions.get_session(SSOSessionId(sso_cookie_val))

    def add_test_user_tou(self, eppn: str | None = None, version: str | None = None) -> tuple[IdPUser, ToUEvent]:
        """Utility function to add a valid ToU to the default test user"""
        if version is None:
            version = self.app.conf.tou_version
        if eppn is None:
            eppn = self.test_user.eppn

        # load user from central db to not get out of sync
        user = self.app.userdb.lookup_user(eppn)
        assert user is not None

        tou = ToUEvent(
            version=version,
            created_by="idp_tests",
            created_ts=utc_now(),
            modified_ts=utc_now(),
            event_id=str(ObjectId()),
        )
        user.tou.add(tou)
        self.request_user_sync(user)
        return user, tou

    def add_test_user_mail_address(self, mail_address: MailAddress) -> None:
        """Utility function to add a mail address to the default test user"""
        # load user from central db to not get out of sync
        user = self.app.userdb.lookup_user(self.test_user.eppn)
        assert user is not None

        user.mail_addresses.add(mail_address)
        self.request_user_sync(user)

    def add_test_user_security_key(
        self,
        user: User | None = None,
        credential_id: str | None = "webauthn_keyhandle",
        is_verified: bool = False,
        mfa_approved: bool = False,
        credential: FidoCredential | None = None,
        always_use_security_key: bool = True,
    ) -> None:
        if user is None:
            user = self.test_user
        # load user from central db to not get out of sync
        user = self.app.userdb.lookup_user(user.eppn)
        assert user is not None

        if credential is None:
            credential = Webauthn(
                keyhandle=credential_id,
                credential_data="test",
                app_id="test",
                description="test security key",
                created_by="test",
                authenticator=AuthenticatorAttachment.CROSS_PLATFORM,
                is_verified=is_verified,
                mfa_approved=mfa_approved,
            )
        user.credentials.add(credential)
        user.preferences.always_use_security_key = always_use_security_key
        self.request_user_sync(user)

    def add_test_user_external_mfa_cred(
        self, user: User | None = None, trust_framework: TrustFramework | None = None, trust_level: str | None = None
    ) -> ExternalCredential:
        if user is None:
            user = self.test_user
        # load user from central db to not get out of sync
        user = self.app.userdb.lookup_user(user.eppn)
        assert user is not None

        if trust_framework is None:
            trust_framework = TrustFramework.SWECONN

        if trust_level is None:
            trust_level = "loa3"

        cred = external_credential_from_dict(
            {"framework": trust_framework, "level": trust_level, "created_ts": utc_now(), "created_by": "test"}
        )
        assert cred is not None  # please mypy
        user.credentials.add(cred)
        self.request_user_sync(user)
        return cred

    def get_attributes(self, result: LoginResultAPI, saml2_client: Saml2Client | None = None) -> dict[str, list[Any]]:
        assert result.finished_result is not None
        authn_response = self.parse_saml_authn_response(result.finished_result, saml2_client=saml2_client)
        session_info = authn_response.session_info()
        attributes: dict[str, list[Any]] = session_info["ava"]
        return attributes

    def _assert_dict_contains(self, actual: dict[str, Any], expected: dict[str, Any]) -> None:
        for key, value in expected.items():
            assert key in actual, f"expected {key} not in {actual}"
            if isinstance(value, dict):
                self._assert_dict_contains(actual[key], value)
            else:
                assert actual[key] == value, f"expected {key} value: {actual[key]} != {value} in {actual}"

    def _check_login_result(
        self,
        result: LoginResultAPI,
        visit_order: list[IdPAction],
        sso_cookie_val: str | bool | None = True,
        finish_result: FinishedResultAPI | None = None,
        pwauth_result: PwAuthResult | None = None,
        error: dict[str, Any] | None = None,
    ) -> None:
        assert result.visit_order == visit_order, f"visit_order: {result.visit_order}, expected: {visit_order}"

        if sso_cookie_val is True:
            assert result.sso_cookie_val is not None, "Expected sso_cookie_val but it is None"
        else:
            assert result.sso_cookie_val == sso_cookie_val, (
                f"sso_cookie_val: {result.sso_cookie_val}, expected: {sso_cookie_val}"
            )

        if finish_result is not None:
            assert result.finished_result is not None, "Expected finished_result but it is None"
            self._assert_dict_contains(result.finished_result.payload, finish_result.payload)

        if pwauth_result is not None:
            assert result.pwauth_result is not None, "Expected pwauth_result but it is None"
            self._assert_dict_contains(result.pwauth_result.payload, pwauth_result.payload)

        if error is not None:
            assert result.error is not None, "Expected error but it is None"
            self._assert_dict_contains(result.error, error)
