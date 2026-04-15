from collections.abc import Mapping
from typing import Any

import pytest

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.config.parsers import load_config
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.common.authn.utils import no_authn_views
from eduid.webapp.common.session import session
from eduid.webapp.common.session.eduid_session import EduidSession
from eduid.webapp.common.session.namespaces import LoginApplication

__author__ = "lundberg"


class SessionTestConfig(EduIDBaseAppConfig):
    pass


class SessionTestApp(AuthnBaseApp[SessionTestConfig]):
    def __init__(self, config: SessionTestConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)


def session_init_app(name: str, test_config: Mapping[str, Any]) -> SessionTestApp:
    config = load_config(typ=SessionTestConfig, app_name=name, ns="webapp", test_config=test_config)
    app = SessionTestApp(config, init_central_userdb=False)
    no_authn_views(config, ["/unauthenticated"])

    @app.route("/authenticated", methods=["GET"])
    def authenticated() -> str:
        session["authenticated_request"] = True
        return "Hello, World!"

    @app.route("/unauthenticated", methods=["GET"])
    def unauthenticated() -> str:
        session["unauthenticated_request"] = True
        return "Hello, World!"

    @app.route("/return-session-key-test", methods=["GET"])
    def return_session_key_test() -> str:
        ret = session["test"]
        assert isinstance(ret, str)
        return ret

    @app.route("/common", methods=["GET"])
    def common() -> str:
        session.common.eppn = "hubba-bubba"
        session.common.is_logged_in = True
        session.common.login_source = LoginApplication["authn"]
        return "Hello, World!"

    @app.route("/mfa-action", methods=["GET"])
    def mfa_action() -> str:
        session.mfa_action.success = True
        session.mfa_action.issuer = "https://issuer-entity-id.example.com"
        session.mfa_action.authn_instant = "2019-03-21T16:26:17Z"
        session.mfa_action.authn_context = "http://id.elegnamnden.se/loa/1.0/loa3"
        return "Hello, World!"

    @app.route("/reset-password", methods=["GET"])
    def reset_password() -> str:
        session.reset_password.generated_password_hash = "password-hash"
        return "Hello, World!"

    @app.route("/signup", methods=["GET"])
    def signup() -> str:
        session.signup.email.verification_code = "email-verification-code"
        return "Hello, World!"

    @app.route("/logout", methods=["GET"])
    def logout() -> str:
        session.invalidate()
        return "Goodbye"

    return app


class EduidSessionTests(EduidAPITestCase[SessionTestApp]):
    app: SessionTestApp

    @pytest.fixture(autouse=True)
    def setup(self, setup_api: None) -> None:
        self.test_user_eppn = "hubba-bubba"

    def load_app(self, config: Mapping[str, Any]) -> SessionTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return session_init_app("testing", config)

    @pytest.fixture(scope="class")
    def update_config(self) -> dict[str, Any]:
        config = self._get_base_config()
        config.update(
            {
                "debug": True,
                "log_level": "DEBUG",
                "no_authn_urls": [],
            }
        )
        return config

    def test_session_authenticated(self) -> None:
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get("/authenticated")
            assert response.status_code == 200
            with browser.session_transaction() as sess:
                assert sess["authenticated_request"]

    def test_session_unauthenticated(self) -> None:
        with self.browser as browser:
            response = browser.get("/authenticated")
            assert response.status_code == 401

            response = browser.get("/unauthenticated")
            assert response.status_code == 200
            with browser.session_transaction() as sess:
                assert sess["unauthenticated_request"]

    def test_session_transaction(self) -> None:
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            with browser.session_transaction() as sess:
                sess["test"] = "my session value"
            response = browser.get("/return-session-key-test")
            assert response.status_code == 200
            assert response.data.decode("utf-8") == "my session value"

    def test_request_context_session(self) -> None:
        with self.app.test_request_context("/return-session-key-test", method="GET"):
            session["test"] = "another session value"
            session.persist()  # Explicit session.persist is needed when working within a test_request_context
            response = self.app.dispatch_request()
            assert response == "another session value"

    def test_session_common(self) -> None:
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get("/common")
            assert response.status_code == 200
            with browser.session_transaction() as sess:
                assert sess.common.is_logged_in
                assert sess.common.login_source == LoginApplication("authn")
                assert sess.common.eppn == self.test_user_eppn

    def test_session_mfa_action(self) -> None:
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get("/mfa-action")
            assert response.status_code == 200
            with browser.session_transaction() as sess:
                assert sess.mfa_action.success
                assert sess.mfa_action.issuer == "https://issuer-entity-id.example.com"
                assert sess.mfa_action.authn_instant == "2019-03-21T16:26:17Z"
                assert sess.mfa_action.authn_context == "http://id.elegnamnden.se/loa/1.0/loa3"

    def test_session_reset_password(self) -> None:
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get("/reset-password")
            assert response.status_code == 200
            with browser.session_transaction() as sess:
                assert sess.reset_password.generated_password_hash == "password-hash"

    def test_session_signup(self) -> None:
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get("/signup")
            assert response.status_code == 200
            with browser.session_transaction() as sess:
                assert sess.signup.email.verification_code == "email-verification-code"

    def test_clear_session_mfa_action(self) -> None:
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get("/mfa-action")
            assert response.status_code == 200
            with browser.session_transaction() as sess:
                assert sess.mfa_action.success
                assert sess.mfa_action.issuer == "https://issuer-entity-id.example.com"
                assert sess.mfa_action.authn_instant == "2019-03-21T16:26:17Z"
                assert sess.mfa_action.authn_context == "http://id.elegnamnden.se/loa/1.0/loa3"
                del sess.mfa_action

            with browser.session_transaction() as sess:
                assert not sess.mfa_action.success
                assert sess.mfa_action.issuer is None
                assert sess.mfa_action.authn_instant is None
                assert sess.mfa_action.authn_context is None

    def test_remove_cookie_on_invalidated_session_save(self) -> None:
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get("/logout")

        cookie_headers = [header for header in response.headers if header[0] == "Set-Cookie"]
        for cookie in cookie_headers:
            keyvalues = cookie[1].split(";")
            for keyvalue in keyvalues:
                value = keyvalue.split("=")
                if value[0].strip() == self.app.conf.flask.session_cookie_name:
                    assert value[1] == ""
                elif value[0].strip() == "expires":
                    assert value[1] == "Thu, 01 Jan 1970 00:00:00 GMT"

    def _test_bad_session_cookie(self, bad_cookie_value: str) -> None:
        with self.browser as browser:
            browser.set_cookie(domain=".test.localhost", key="sessid", value=bad_cookie_value)
            response = browser.get("/unauthenticated")
            # Make sure the request completes correctly even with a bad cookie value
            assert response.status_code == 200
            with browser.session_transaction() as sess:
                assert sess["unauthenticated_request"]

    def test_bad_session_cookie(self) -> None:
        self._test_bad_session_cookie(
            """aNDCJ7WPO4A5RB4D2N6QIOTUXCOSCV43LGCB4PJC4ILCIVWSR7RBLOZYIUPS42UTV5SJMNXQE44L6YHOVBIOUKUBBKV6ZRF6KA4WZ3KT\
            Y';.")"""
        )
        self._test_bad_session_cookie(
            """aNDCJ7WPO4A5RB4D2N6QIOTUXCOSCV43LGCB4PJC4ILCIVWSR7RBLOZYIUPS42UTV5SJMNXQE44L6YHOVBIOUKUBBKV6ZRF6KA4WZ3KT\
            Y" or sleep(4) # """
        )
        self._test_bad_session_cookie("-1839%2Bor%2B1=2")

    def test_timestamp_update(self) -> None:
        with self.browser as browser:
            with browser.session_transaction() as sess:
                assert isinstance(sess, EduidSession)
                sess.idp.sso_cookie_val = "first"
                sess._serialize_namespaces()
                ts1 = sess.idp.ts
                # change something (anything) in the timestamped namespace
                sess.idp.sso_cookie_val = "second"
                sess._serialize_namespaces()
                ts2 = sess.idp.ts
                # verify the timestamp was updated when the content changed
                assert ts1 != ts2

    def test_timestamp_dynamic_default(self) -> None:
        """Verify that not all timestamped namespaces get the same timestamp as default"""
        with self.browser as browser:
            with browser.session_transaction() as sess:
                assert isinstance(sess, EduidSession)
                assert sess.idp.ts != sess.signup.ts
