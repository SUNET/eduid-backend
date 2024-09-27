import base64
import json
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from flask import Blueprint
from saml2.s_utils import deflate_and_base64_encode
from werkzeug.exceptions import NotFound
from werkzeug.http import dump_cookie

from eduid.common.config.base import FrontendAction
from eduid.common.config.parsers import load_config
from eduid.common.misc.timeutil import utc_now
from eduid.common.models.saml2 import EduidAuthnContextClass
from eduid.webapp.authn.app import AuthnApp, authn_init_app
from eduid.webapp.authn.settings.common import AuthnConfig
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.cache import OutstandingQueriesCache
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.common.authn.tests.responses import auth_response, logout_request, logout_response
from eduid.webapp.common.authn.utils import no_authn_views
from eduid.webapp.common.session import EduidSession, session
from eduid.webapp.common.session.namespaces import AuthnRequestRef

logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


@dataclass
class AcsResult:
    session: EduidSession
    authn_ref: AuthnRequestRef


class AuthnAPITestBase(EduidAPITestCase):
    """Test cases for the real eduid-authn app"""

    app: AuthnApp

    def setUp(  # type: ignore[override]
        self,
        *args: list[Any],
        users: list[str] | None = None,
        copy_user_to_private: bool = False,
        **kwargs: dict[str, Any],
    ) -> None:
        super().setUp(*args, users=users, copy_user_to_private=copy_user_to_private, **kwargs)
        self.idp_url = "https://idp.example.com/simplesaml/saml2/idp/SSOService.php"

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        saml_config = os.path.join(HERE, "saml2_settings.py")
        config.update(
            {
                "saml2_login_redirect_url": "/",
                "saml2_logout_redirect_url": "/logged-out",
                "saml2_settings_module": saml_config,
                "saml2_strip_saml_user_suffix": "@test.eduid.se",
                "signup_authn_failure_redirect_url": "http://test.localhost/failure",
                "signup_authn_success_redirect_url": "http://test.localhost/success",
                "enable_authn_json_response": True,
                "frontend_action_authn_parameters": {
                    FrontendAction.LOGIN.value: {
                        "same_user": False,
                        "finish_url": "https://example.com/login/ext-return/{app_name}/{authn_id}",
                    },
                    FrontendAction.CHANGE_PW_AUTHN.value: {
                        "force_authn": True,
                        "high_security": True,
                        "finish_url": "https://example.com/profile/ext-return/{app_name}/{authn_id}",
                    },
                    FrontendAction.TERMINATE_ACCOUNT_AUTHN.value: {
                        "force_authn": True,
                        "high_security": True,
                        "finish_url": "https://example.com/profile/ext-return/{app_name}/{authn_id}",
                    },
                    FrontendAction.REMOVE_SECURITY_KEY_AUTHN.value: {
                        "force_mfa": True,
                        "finish_url": "https://example.com/profile/ext-return/{app_name}/{authn_id}",
                    },
                },
            }
        )
        return config

    def load_app(self, test_config: Mapping[str, Any]) -> AuthnApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return authn_init_app(test_config=test_config)

    def add_outstanding_query(self, authn_id: AuthnRequestRef) -> str:
        """
        Add a SAML2 authentication query to the queries cache.
        To be used before accessing the assertion consumer service.

        :return: the session token corresponding to the query
        """
        with self.app.test_request_context("/authenticate"):
            self.app.dispatch_request()
            oq_cache = OutstandingQueriesCache(session.authn.sp.pysaml2_dicts)
            cookie_val = session.meta.cookie_val
            oq_cache.set(cookie_val, authn_id)
            session.persist()  # Explicit session.persist is needed when working within a test_request_context
            return cookie_val

    def start_authenticate(self, eppn: str, frontend_action: FrontendAction) -> str:
        """
        Add a SAML2 authentication query to the queries cache,
        build a cookie with a session id corresponding to the added query,
        build a SAML2 authn response for the added query,
        and send both to the assertion consumer service,
        so that the user is logged in (the session corresponding to the cookie
        has her eppn).
        This method returns the cookie that has to be sent with any
        subsequent request that needs to be authenticated.

        :return: the session id corresponding to the authn session
        """
        res = self.acs("/authenticate", eppn=eppn, frontend_action=frontend_action)
        session_id = res.session.meta.cookie_val
        logger.debug(f"Test logged in, got cookie {session_id}")
        return session_id

    def authn(self, url: str, frontend_action: FrontendAction) -> None:
        """
        Common code for the tests that need to send an authentication request.
        This checks that the client is redirected to the idp.

        :param url: the url of the desired authentication mode.
        :param frontend_action: the frontend action to send to the service
        """
        with self.session_cookie_anon(self.browser, logged_in=False) as browser:
            logger.debug(f"Test POST to {url} with frontend action {frontend_action}")
            with browser.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()  # the session need to be created
            with browser.session_transaction() as sess:
                resp = browser.post(url, json={"frontend_action": frontend_action.value, "csrf_token": csrf_token})
            logger.debug(f"Test fetched {url}, response {resp}")

            with browser.session_transaction() as sess:
                request_id, authn_ref = self._get_request_id_from_session(sess)
                logger.debug(f"Test ACS got SAML request id {request_id} from session {sess}")
                # save the authn_data for further checking below
                authn = sess.authn.sp.authns[authn_ref]

        assert resp.status_code == 200
        payload = self.get_response_payload(resp)
        assert payload["location"].startswith(self.idp_url)
        logger.debug(f"Test got the expected redirect to the IdP {self.idp_url}")
        assert self.app.conf.frontend_action_authn_parameters[frontend_action].finish_url == authn.finish_url

    def _get_request_id_from_session(self, session: EduidSession) -> tuple[str, AuthnRequestRef]:
        """extract the (probable) SAML request ID from the session"""
        oq_cache = OutstandingQueriesCache(session.authn.sp.pysaml2_dicts)
        ids = oq_cache.outstanding_queries().keys()
        if len(ids) != 1:
            raise RuntimeError(f"More or less than one ({len(ids)}) authn request in the session")
        saml_req_id = list(ids)[0]
        req_ref = AuthnRequestRef(oq_cache.outstanding_queries()[saml_req_id])
        return saml_req_id, req_ref

    def acs(
        self,
        url: str,
        eppn: str,
        frontend_action: FrontendAction,
        frontend_state: str | None = None,
        accr: EduidAuthnContextClass | None = None,
    ) -> AcsResult:
        """
        common code for the tests that need to access the assertion consumer service
        and then check the side effects of this access.

        :param url: the url of the desired authentication endpoint
        :param eppn: the eppn of the user to access the service
        :param frontend_action: the requested frontend action
        :param frontend_state: the frontend state to send to the service
        :param accr: the authentication context class reference returned from the IdP
        :return: the result of the ACS call
        """
        with self.session_cookie_anon(self.browser) as browser:
            logger.debug(f"Test POST to {url} with frontend action {frontend_action}")
            with browser.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()  # the session need to be created

            data = {
                "frontend_action": frontend_action.value,
                "csrf_token": csrf_token,
            }
            if frontend_state:
                data["frontend_state"] = frontend_state
            resp = browser.post(url, json=data)
            logger.debug(f"Test fetched {url}, response {resp}")
            self._check_success_response(response=resp, type_="POST_AUTHN_AUTHENTICATE_SUCCESS")

            with browser.session_transaction() as sess:
                request_id, authn_ref = self._get_request_id_from_session(sess)
                logger.debug(f"Test ACS got SAML request id {request_id} from session {sess}")

            authr = auth_response(request_id, eppn, accr=accr).encode("utf-8")
            data = {
                "csrf": sess.get_csrf_token(),
                "SAMLResponse": base64.b64encode(authr).decode(),
            }

            resp = browser.post("/saml2-acs", data=data)

            assert resp.status_code == 302
            assert resp.location == self.app.conf.frontend_action_authn_parameters[frontend_action].finish_url.format(
                app_name="authn", authn_id=authn_ref
            )
            resp = browser.post("/get-status", json={"authn_id": authn_ref, "csrf_token": csrf_token})
            payload = self.get_response_payload(response=resp)
            assert payload["error"] is False
            assert payload["frontend_action"] == frontend_action.value
            if frontend_state:
                assert payload["frontend_state"] == frontend_state
            with browser.session_transaction() as sess:
                return AcsResult(session=sess, authn_ref=authn_ref)

    def dump_session_cookie(self, session_id: str) -> str:
        """
        Get a cookie corresponding to an authenticated session.

        :param session_id: the token for the session

        :return: the cookie
        """
        return dump_cookie(
            self.app.conf.flask.session_cookie_name,
            session_id,
            max_age=int(self.app.conf.flask.permanent_session_lifetime),
            path=self.app.conf.flask.session_cookie_path,
            domain=self.app.conf.flask.session_cookie_domain,
        )


class AuthnAPITestCase(AuthnAPITestBase):
    """
    Tests to check the different modes of authentication.
    """

    app: AuthnApp

    def setUp(self, **kwargs):
        super().setUp(users=["hubba-bubba", "hubba-fooo"], **kwargs)

    def test_login_authn(self):
        self.authn("/authenticate", FrontendAction.LOGIN)

    def test_chpass_authn(self):
        self.authn("/authenticate", FrontendAction.CHANGE_PW_AUTHN)

    def test_terminate_authn(self):
        self.authn("/authenticate", FrontendAction.TERMINATE_ACCOUNT_AUTHN)

    def test_login_assertion_consumer_service(self):
        for accr in EduidAuthnContextClass:
            if accr == EduidAuthnContextClass.NOT_IMPLEMENTED:
                accr = None
            eppn = "hubba-bubba"
            res = self.acs("/authenticate", eppn, frontend_action=FrontendAction.LOGIN, accr=accr)
            assert res.session.common.eppn == "hubba-bubba"
            authn = res.session.authn.sp.authns[res.authn_ref]
            assert authn.frontend_action == FrontendAction.LOGIN
            if accr:
                assert authn.asserted_authn_ctx == accr.value

    def test_assertion_consumer_service(self):
        actions = [FrontendAction.LOGIN, FrontendAction.CHANGE_PW_AUTHN, FrontendAction.TERMINATE_ACCOUNT_AUTHN]
        for action in actions:
            res = self.acs("/authenticate", eppn=self.test_user.eppn, frontend_action=action)
            assert res.session.common.eppn == self.test_user.eppn
            assert res.session.common.is_logged_in is True
            authn = res.session.authn.sp.authns[res.authn_ref]
            assert authn.frontend_action == action
            assert authn.authn_instant is not None
            age = utc_now() - authn.authn_instant
            assert 10 < age.total_seconds() < 15

    def test_frontend_state(self):
        eppn = "hubba-bubba"
        self.acs("/authenticate", eppn, FrontendAction.REMOVE_SECURITY_KEY_AUTHN, frontend_state="key_id_to_remove")

    def _signup_authn_user(self, eppn):
        timestamp = utc_now()

        with self.app.test_client() as c:
            with self.app.test_request_context("/signup-authn"):
                c.set_cookie(
                    domain="test.localhost",
                    key=self.app.conf.flask.session_cookie_name,
                    value=session.meta.cookie_val[16:],
                )
                session.common.eppn = eppn
                session.signup.ts = timestamp

                return self.app.dispatch_request()


class AuthnTestApp(AuthnBaseApp):
    def __init__(self, config: AuthnConfig, **kwargs):
        super().__init__(config, **kwargs)
        self.conf = config


class UnAuthnAPITestCase(EduidAPITestCase):
    """Tests for a fictitious app based on AuthnBaseApp"""

    app: AuthnTestApp

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        saml_config = os.path.join(HERE, "saml2_settings.py")
        config.update(
            {
                "saml2_login_redirect_url": "/",
                "saml2_logout_redirect_url": "/",
                "saml2_settings_module": saml_config,
                "saml2_strip_saml_user_suffix": "@test.eduid.se",
            }
        )
        return config

    def load_app(self, test_config: Mapping[str, Any]) -> AuthnTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        config = load_config(typ=AuthnConfig, app_name="testing", ns="webapp", test_config=test_config)
        return AuthnTestApp(config)

    def test_no_cookie(self):
        with self.app.test_client() as c:
            resp = c.get("/")
            self.assertEqual(resp.status_code, 401)

    def test_cookie(self):
        sessid = "fb1f42420b0109020203325d750185673df252de388932a3957f522a6c43aa47"
        self.redis_instance.conn.set(sessid, json.dumps({"v1": {"id": "0"}}))

        with self.session_cookie(self.browser, self.test_user.eppn) as c:
            self.assertRaises(NotFound, c.get, "/")


class NoAuthnAPITestCase(EduidAPITestCase):
    """Tests for a fictitious app based on AuthnBaseApp"""

    app: AuthnTestApp

    def setUp(self):
        super().setUp()
        test_views = Blueprint("testing", __name__)

        @test_views.route("/test")
        def test():
            return "OK"

        @test_views.route("/test2")
        def test2():
            return "OK"

        @test_views.route("/test3")
        def test3():
            return "OK"

        self.app.register_blueprint(test_views)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        saml_config = os.path.join(HERE, "saml2_settings.py")
        config.update(
            {
                "no_authn_urls": ["^/test$"],
                "saml2_login_redirect_url": "/",
                "saml2_logout_redirect_url": "/",
                "saml2_settings_module": saml_config,
                "saml2_strip_saml_user_suffix": "@test.eduid.se",
            }
        )
        return config

    def load_app(self, test_config: Mapping[str, Any]) -> AuthnTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        config = load_config(typ=AuthnConfig, app_name="testing", ns="webapp", test_config=test_config)
        return AuthnTestApp(config)

    def test_no_authn(self):
        with self.app.test_client() as c:
            resp = c.get("/test")
            self.assertEqual(resp.status_code, 200)

    def test_authn(self):
        with self.app.test_client() as c:
            resp = c.get("/test2")
            self.assertEqual(resp.status_code, 401)

    def test_no_authn_util(self):
        no_authn_urls_before = [path for path in self.app.conf.no_authn_urls]
        no_authn_path = "/test3"
        no_authn_views(self.app.conf, [no_authn_path])
        self.assertEqual(no_authn_urls_before + [f"^{no_authn_path!s}$"], self.app.conf.no_authn_urls)

        with self.app.test_client() as c:
            resp = c.get("/test3")
            self.assertEqual(resp.status_code, 200)


class LogoutRequestTests(AuthnAPITestBase):
    def test_metadataview(self):
        with self.app.test_client() as c:
            response = c.get("/saml2-metadata")
            self.assertEqual(response.status, "200 OK")

    def test_logout_nologgedin(self):
        eppn = "hubba-bubba"
        with self.app.test_request_context("/logout", method="GET"):
            # eppn is set in the IdP
            session.common.eppn = eppn
            response = self.app.dispatch_request()
            self.assertEqual(response.status, "302 FOUND")
            self.assertIn(self.app.conf.saml2_logout_redirect_url, response.headers["Location"])

    def test_logout_loggedin(self):
        res = self.acs(url="/authenticate", eppn=self.test_user.eppn, frontend_action=FrontendAction.LOGIN)
        cookie = self.dump_session_cookie(res.session.meta.cookie_val)

        with self.app.test_request_context("/logout", method="GET", headers={"Cookie": cookie}):
            response = self.app.dispatch_request()
            logger.debug(f"Test called /logout, response {response}")
            self.assertEqual(response.status, "302 FOUND")
            self.assertIn(
                "https://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php", response.headers["location"]
            )

    def test_logout_service_startingSP(self):
        session_id = self.start_authenticate(eppn=self.test_user.eppn, frontend_action=FrontendAction.LOGIN)
        cookie = self.dump_session_cookie(session_id)

        with self.app.test_request_context(
            "/saml2-ls",
            method="POST",
            headers={"Cookie": cookie},
            data={
                "SAMLResponse": deflate_and_base64_encode(logout_response(session_id)),
                "RelayState": "/testing-relay-state",
            },
        ):
            response = self.app.dispatch_request()

            self.assertEqual(response.status, "302 FOUND")
            self.assertIn("testing-relay-state", response.location)

    def test_logout_service_startingSP_already_logout(self):
        session_id = self.start_authenticate(eppn=self.test_user.eppn, frontend_action=FrontendAction.LOGIN)

        with self.app.test_request_context(
            "/saml2-ls",
            method="POST",
            data={
                "SAMLResponse": deflate_and_base64_encode(logout_response(session_id)),
                "RelayState": "/testing-relay-state",
            },
        ):
            response = self.app.dispatch_request()

            self.assertEqual(response.status, "302 FOUND")
            self.assertIn("testing-relay-state", response.location)

    def test_logout_service_startingIDP(self):
        res = self.acs("/authenticate", eppn=self.test_user.eppn, frontend_action=FrontendAction.LOGIN)
        cookie = self.dump_session_cookie(res.session.meta.cookie_val)

        with self.app.test_request_context(
            "/saml2-ls",
            method="POST",
            headers={"Cookie": cookie},
            data={
                "SAMLRequest": deflate_and_base64_encode(logout_request("SESSION_ID")),
                "RelayState": "/testing-relay-state",
            },
        ):
            response = self.app.dispatch_request()

            self.assertEqual(response.status, "302 FOUND")
            assert (
                "https://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php?SAMLResponse="
                in response.location
            )

    def test_logout_service_startingIDP_no_subject_id(self):
        eppn = "hubba-bubba"
        res = self.acs("/authenticate", eppn=self.test_user.eppn, frontend_action=FrontendAction.LOGIN)
        session_id = res.session.meta.cookie_val
        cookie = self.dump_session_cookie(session_id)

        saml_response = auth_response(session_id, eppn).encode("utf-8")

        # Log in through IDP SAMLResponse
        with self.app.test_request_context(
            "/saml2-acs",
            method="POST",
            headers={"Cookie": cookie},
            data={
                "SAMLResponse": base64.b64encode(saml_response),
                "RelayState": "/testing-relay-state",
            },
        ):
            self.app.dispatch_request()
            session.persist()  # Explicit session.persist is needed when working within a test_request_context

        with self.app.test_request_context(
            "/saml2-ls",
            method="POST",
            headers={"Cookie": cookie},
            data={
                "SAMLRequest": deflate_and_base64_encode(logout_request(session_id)),
                "RelayState": "/testing-relay-state",
            },
        ):
            session.authn.name_id = None
            session.persist()  # Explicit session.persist is needed when working within a test_request_context
            response = self.app.dispatch_request()

            self.assertEqual(response.status, "302 FOUND")
            self.assertIn("testing-relay-state", response.location)
