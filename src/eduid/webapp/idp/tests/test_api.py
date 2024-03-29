import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any, Mapping, Optional

from bson import ObjectId
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.response import AuthnResponse
from werkzeug.test import TestResponse

from eduid.common.misc.timeutil import utc_now
from eduid.userdb import ToUEvent
from eduid.userdb.mail import MailAddress
from eduid.userdb.user import User
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.cache import IdentityCache, OutstandingQueriesCache, StateCache
from eduid.webapp.common.authn.utils import get_saml2_config
from eduid.webapp.common.session.namespaces import AuthnRequestRef, PySAML2Dicts
from eduid.webapp.idp.app import IdPApp, init_idp_app
from eduid.webapp.idp.helpers import IdPAction
from eduid.webapp.idp.sso_session import SSOSession, SSOSessionId

__author__ = "ft"


logger = logging.getLogger(__name__)


@dataclass
class GenericResult:
    payload: dict[str, Any]


@dataclass
class NextResult(GenericResult):
    error: Optional[dict[str, Any]] = None


@dataclass
class PwAuthResult(GenericResult):
    sso_cookie_val: Optional[str] = None
    cookies: dict[str, Any] = field(default_factory=dict)


@dataclass
class TouResult(GenericResult):
    pass


@dataclass
class FinishedResultAPI(GenericResult):
    pass


@dataclass
class TestUser:
    eppn: Optional[str]
    password: Optional[str]


@dataclass
class LoginResultAPI:
    response: TestResponse
    ref: Optional[str] = None
    sso_cookie_val: Optional[str] = None
    visit_count: dict[str, int] = field(default_factory=dict)
    visit_order: list[IdPAction] = field(default_factory=list)
    pwauth_result: Optional[PwAuthResult] = None
    tou_result: Optional[TouResult] = None
    finished_result: Optional[FinishedResultAPI] = None
    error: Optional[dict[str, Any]] = None


class IdPAPITests(EduidAPITestCase[IdPApp]):
    """Base TestCase for those tests that need a full environment setup"""

    default_user: TestUser

    def setUp(
        self,
        *args,
        **kwargs,
    ):
        super().setUp(*args, **kwargs)
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

    def load_app(self, config: Optional[Mapping[str, Any]]) -> IdPApp:
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
                "other_device_secret_key": "lx0sg0g21QUkiu9JAPfhx4hJ5prJtbk1PPE-OBvpiAk=",
                "known_devices_secret_key": "WwemHQgPm1hpx41NYaVBQpRV7BAq0OMtfF3k4H72J7c=",
                "geo_statistics_secret_key": "gk5cBWIZ6k-mNHWnA33ZpsgXfgH50Wi_s3mUNI9GF0o=",
            }
        )
        return config

    def _try_login(
        self,
        saml2_client: Optional[Saml2Client] = None,
        authn_context: Optional[Mapping[str, Any]] = None,
        force_authn: bool = False,
        assertion_consumer_service_url: Optional[str] = None,
        test_user: Optional[TestUser] = None,
        sso_cookie_val: Optional[str] = None,
    ) -> LoginResultAPI:
        """
        Try logging in to the IdP.

        :return: Information about how far we got (reached LoginState) and the last response instance.
        """
        _saml2_client = saml2_client if saml2_client is not None else self.saml2_client

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

        path = self._extract_path_from_info(info)

        user: TestUser = test_user if test_user is not None else self.default_user

        with self.session_cookie_anon(self.browser) as browser:
            # Send SAML request to SAML endpoint, expect a redirect to the login bundle back
            resp = browser.get(path)
            if resp.status_code != 302:
                return LoginResultAPI(response=resp)

            redirect_loc = self._extract_path_from_response(resp)
            ref = redirect_loc.split("/")[-1]

            result = LoginResultAPI(ref=ref, response=resp)

            cookie_jar = {}
            if sso_cookie_val is not None:
                cookie_jar["idpauthn"] = sso_cookie_val

            while True:
                logger.info(f"Main API test loop, current state: {result}")

                # Call the 'next' endpoint
                _next = self._call_next(ref)

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

                if _action == IdPAction.PWAUTH:
                    if not user.eppn or not user.password:
                        logger.error(f"Can't login without username and password, aborting with result {result}")
                        return result

                    result.pwauth_result = self._call_pwauth(_next.payload["target"], ref, user.eppn, user.password)
                    result.sso_cookie_val = result.pwauth_result.sso_cookie_val
                    cookie_jar.update(result.pwauth_result.cookies)

                if _action == IdPAction.MFA:
                    # Not implemented yet
                    return result

                if _action == IdPAction.TOU:
                    result.tou_result = self._call_tou(
                        _next.payload["target"], ref, user_accepts=self.app.conf.tou_version
                    )

                if _action == IdPAction.FINISHED:
                    result.finished_result = FinishedResultAPI(payload=_next.payload)
                    return result

    def _call_next(self, ref: str) -> NextResult:
        with self.session_cookie_anon(self.browser) as client:
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

    def _call_pwauth(self, target: str, ref: str, username: str, password: str) -> PwAuthResult:
        with self.session_cookie_anon(self.browser) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"ref": ref, "username": username, "password": password, "csrf_token": sess.get_csrf_token()}
                response = client.post(target, data=json.dumps(data), content_type=self.content_type_json)
        logger.debug(f"PwAuth endpoint returned:\n{json.dumps(response.json, indent=4)}")
        result = PwAuthResult(payload=self.get_response_payload(response))
        cookies = response.headers.get("Set-Cookie")
        if not cookies:
            return result

        # Save the SSO cookie value
        _re = f".*{self.app.conf.sso_cookie.key}=(.+?);.*"
        _sso_cookie_re = re.match(_re, cookies)
        if _sso_cookie_re:
            result.sso_cookie_val = _sso_cookie_re.groups()[0]

        if result.sso_cookie_val:
            result.cookies = {self.app.conf.sso_cookie.key: result.sso_cookie_val}

        return result

    def _call_tou(self, target: str, ref: str, user_accepts: Optional[str]) -> TouResult:
        with self.session_cookie_anon(self.browser) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"ref": ref, "csrf_token": sess.get_csrf_token()}
                    if user_accepts:
                        data["user_accepts"] = user_accepts
                response = client.post(target, data=json.dumps(data), content_type=self.content_type_json)
        logger.debug(f"ToU endpoint returned:\n{json.dumps(response.json, indent=4)}")
        result = TouResult(payload=self.get_response_payload(response))
        return result

    @staticmethod
    def _extract_form_inputs(res: str) -> dict[str, Any]:
        inputs = {}
        for line in res.split("\n"):
            if "input" in line:
                # YOLO
                m = re.match(".*<input .* name=['\"](.+?)['\"].*value=['\"](.+?)['\"]", line)
                if m:
                    name, value = m.groups()
                    inputs[name] = value.strip("'\"")
        return inputs

    def _extract_path_from_response(self, response: TestResponse) -> str:
        return self._extract_path_from_info({"headers": response.headers})

    def _extract_path_from_info(self, info: Mapping[str, Any]) -> str:
        _location_headers = [_hdr for _hdr in info["headers"] if _hdr[0] == "Location"]
        # get first Location URL
        loc = _location_headers[0][1]
        return self._extract_path_from_url(loc)

    def _extract_path_from_url(self, url):
        # It is a complete URL, extract the path from it (8 is to skip over slashes in https://)
        _idx = url[8:].index("/")
        path = url[8 + _idx :]
        return path

    def parse_saml_authn_response(
        self, result: FinishedResultAPI, saml2_client: Optional[Saml2Client] = None
    ) -> AuthnResponse:
        _saml2_client = saml2_client if saml2_client is not None else self.saml2_client

        xmlstr = result.payload["parameters"]["SAMLResponse"]
        outstanding_queries = self.pysaml2_oq.outstanding_queries()
        return _saml2_client.parse_authn_request_response(xmlstr, BINDING_HTTP_POST, outstanding_queries)

    def get_sso_session(self, sso_cookie_val: str) -> Optional[SSOSession]:
        if sso_cookie_val is None:
            return None
        return self.app.sso_sessions.get_session(SSOSessionId(sso_cookie_val))

    def add_test_user_tou(self, user: Optional[User] = None, version: Optional[str] = None) -> ToUEvent:
        """Utility function to add a valid ToU to the default test user"""
        if version is None:
            version = self.app.conf.tou_version
        if user is None:
            user = self.test_user
        tou = ToUEvent(
            version=version,
            created_by="idp_tests",
            created_ts=utc_now(),
            modified_ts=utc_now(),
            event_id=str(ObjectId()),
        )
        user.tou.add(tou)
        self.amdb.save(user)
        return tou

    def add_test_user_mail_address(self, mail_address: MailAddress) -> None:
        """Utility function to add a mail address to the default test user"""
        self.test_user.mail_addresses.add(mail_address)
        self.amdb.save(self.test_user)

    def get_attributes(self, result, saml2_client: Optional[Saml2Client] = None):
        assert result.finished_result is not None
        authn_response = self.parse_saml_authn_response(result.finished_result, saml2_client=saml2_client)
        session_info = authn_response.session_info()
        attributes: dict[str, list[Any]] = session_info["ava"]
        return attributes
