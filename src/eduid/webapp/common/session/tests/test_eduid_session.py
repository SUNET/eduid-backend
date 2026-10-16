import time
from collections.abc import Callable, Mapping
from typing import Any, cast

import pytest
from flask import Response, request
from pytest_mock import MockerFixture

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.config.parsers import load_config
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.common.authn.utils import no_authn_views
from eduid.webapp.common.session import session
from eduid.webapp.common.session.eduid_session import (
    EduidSession,
    SessionFactory,
    _all_safe_to_lose,
    _path_matches,
)
from eduid.webapp.common.session.namespaces import IdP_SAMLPendingRequest, LoginApplication, RequestRef
from eduid.webapp.common.session.redis_session import RedisEncryptedSession, SessionOutOfSync

__author__ = "lundberg"


class SessionTestConfig(EduIDBaseAppConfig):
    pass


class SessionTestApp(AuthnBaseApp):
    conf: SessionTestConfig

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

    @classmethod
    def load_app(cls, config: Mapping[str, Any]) -> SessionTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return session_init_app("testing", config)

    @pytest.fixture(scope="class")
    @classmethod
    def update_config(cls) -> dict[str, Any]:
        config = cls._get_base_config()
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

    def _new_cookie(self) -> str:
        """Create and persist a session with some idp data, return its cookie value"""
        with self.app.test_request_context():
            sess = self.app.session_interface.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            sess.idp.sso_cookie_val = "first"
            sess.persist()
            return sess.meta.cookie_val

    def _headers(self, cookie_val: str) -> dict[str, str]:
        return {"Cookie": f"{self.app.conf.flask.session_cookie_name}={cookie_val}"}

    def _new_cookie_with_request(self) -> tuple[str, RequestRef]:
        """Create and persist a session with an idp pending request, return its cookie value and the request ref"""
        ref = RequestRef("test-ref")
        with self.app.test_request_context():
            sess = self.app.session_interface.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            sess.idp.sso_cookie_val = "first"
            sess.idp.pending_requests[ref] = IdP_SAMLPendingRequest(request="req", binding="binding")
            sess.persist()
            return sess.meta.cookie_val, ref

    def _lose_conflict(
        self,
        mocker: MockerFixture,
        change: Callable[[EduidSession], None],
        other_writer: Callable[[RedisEncryptedSession], None] | None = None,
    ) -> tuple[Any, Any, Response, Any, Any, str]:
        """
        Open a session, apply `change`, let another writer commit first, and run save_session.

        The other writer adds the key 'other' unless `other_writer` is given. It must commit itself.

        :returns: (outcome exception or None, count spy, response, commit spy, session, cookie_val)
        """
        cookie_val, ref = self._new_cookie_with_request()
        factory = self.app.session_interface
        assert isinstance(factory, SessionFactory)
        self._ref = ref
        with self.app.test_request_context(headers=self._headers(cookie_val)):
            sess = factory.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            change(sess)

            other = factory.manager.get_session(meta=sess.meta, new=False)
            if other_writer is None:
                other["other"] = "writer"
                other.commit()
            else:
                other_writer(other)

            count_spy = mocker.spy(self.app.stats, "count")
            commit_spy = mocker.spy(sess._session, "commit")
            response = Response()
            exc: Exception | None = None
            try:
                factory.save_session(self.app, sess, response)
            except SessionOutOfSync as e:
                exc = e
            # A repeated save (error path) is a no-op, no second commit attempt, no new exception
            factory.save_session(self.app, sess, Response())
            assert commit_spy.call_count == 1
            try:
                db = factory.manager.get_session(meta=sess.meta, new=False)
            except KeyError:
                db = factory.manager.get_session(meta=sess.meta, new=True)  # key was deleted, empty session
            return exc, count_spy, response, commit_spy, db, cookie_val

    def _assert_lost_not_persisted(self, db: RedisEncryptedSession) -> None:
        assert db["other"] == "writer"
        assert db.to_dict()["idp"]["sso_cookie_val"] == "first"
        assert db.to_dict()["idp"]["pending_requests"][self._ref]["used"] is False

    def test_save_session_swallows_out_of_sync_for_allowlisted_paths(self, mocker: MockerFixture) -> None:
        def change(sess: EduidSession) -> None:
            sess.idp.pending_requests[RequestRef("test-ref")].used = True
            sess.idp.sso_cookie_val = "mine"

        exc, count_spy, response, _commit_spy, db, cookie_val = self._lose_conflict(mocker, change)
        assert exc is None
        count_spy.assert_any_call("session_out_of_sync_error")
        count_spy.assert_any_call("session_state_lost")
        cookies = response.headers.getlist("Set-Cookie")
        assert any(c.startswith(f"{self.app.conf.flask.session_cookie_name}={cookie_val}") for c in cookies)
        self._assert_lost_not_persisted(db)

    @staticmethod
    def _allowlisted_change(sess: EduidSession) -> None:
        sess.idp.pending_requests[RequestRef("test-ref")].used = True
        sess.idp.sso_cookie_val = "mine"

    def test_save_session_reraises_when_key_deleted_by_logout(self, mocker: MockerFixture) -> None:
        def logout(other: RedisEncryptedSession) -> None:
            other.clear()  # deletes the key in redis

        exc, count_spy, response, _commit_spy, db, _cookie = self._lose_conflict(
            mocker, self._allowlisted_change, other_writer=logout
        )
        assert isinstance(exc, SessionOutOfSync)
        assert mocker.call("session_state_lost") not in count_spy.call_args_list
        assert not response.headers.getlist("Set-Cookie")
        assert db.to_dict() == {}

    def test_save_session_reraises_when_key_recreated_after_logout(self, mocker: MockerFixture) -> None:
        def logout_and_new_login(other: RedisEncryptedSession) -> None:
            other.clear()
            other["fresh"] = "content"
            other.commit()

        exc, count_spy, _response, _commit_spy, db, _cookie = self._lose_conflict(
            mocker, self._allowlisted_change, other_writer=logout_and_new_login
        )
        assert isinstance(exc, SessionOutOfSync)
        assert mocker.call("session_state_lost") not in count_spy.call_args_list
        assert db.to_dict() == {"fresh": "content"}

    def test_save_session_reraises_when_other_writer_removed_a_path(self, mocker: MockerFixture) -> None:
        def remove_path(other: RedisEncryptedSession) -> None:
            del other["idp"]
            other.commit()

        exc, _count_spy, _response, _commit_spy, _db, _cookie = self._lose_conflict(
            mocker, self._allowlisted_change, other_writer=remove_path
        )
        assert isinstance(exc, SessionOutOfSync)

    def test_save_session_swallows_when_other_writer_only_added_and_changed(self, mocker: MockerFixture) -> None:
        def mfa_auth_like(other: RedisEncryptedSession) -> None:
            data = other.to_dict()
            idp = dict(data["idp"])
            idp["sso_cookie_val"] = "theirs"
            other["idp"] = idp
            other["mfa_action"] = {"success": True}
            other["new_key"] = "x"
            other.commit()

        exc, count_spy, _response, _commit_spy, db, _cookie = self._lose_conflict(
            mocker, self._allowlisted_change, other_writer=mfa_auth_like
        )
        assert exc is None
        count_spy.assert_any_call("session_state_lost")
        assert db["new_key"] == "x"
        assert db.to_dict()["idp"]["sso_cookie_val"] == "theirs"

    def test_save_session_reraises_out_of_sync_for_mixed_paths(self, mocker: MockerFixture) -> None:
        def change(sess: EduidSession) -> None:
            sess.idp.pending_requests[RequestRef("test-ref")].used = True
            sess.common.eppn = "hrrebwn7"

        exc, count_spy, _response, _commit_spy, db, _cookie = self._lose_conflict(mocker, change)
        assert isinstance(exc, SessionOutOfSync)
        count_spy.assert_any_call("session_out_of_sync_error")
        assert mocker.call("session_state_lost") not in count_spy.call_args_list
        self._assert_lost_not_persisted(db)
        assert "common" not in db.to_dict()

    def test_save_session_reraises_out_of_sync_for_common_eppn(self, mocker: MockerFixture) -> None:
        def change(sess: EduidSession) -> None:
            sess.common.eppn = "hrrebwn7"

        exc, _count_spy, _response, _commit_spy, db, _cookie = self._lose_conflict(mocker, change)
        assert isinstance(exc, SessionOutOfSync)
        assert "common" not in db.to_dict()

    def test_save_session_reraises_out_of_sync_for_whole_pending_request(self, mocker: MockerFixture) -> None:
        def change(sess: EduidSession) -> None:
            sess.idp.pending_requests[RequestRef("new-ref")] = IdP_SAMLPendingRequest(request="r", binding="b")

        exc, _count_spy, _response, _commit_spy, _db, _cookie = self._lose_conflict(mocker, change)
        assert isinstance(exc, SessionOutOfSync)

    def test_save_session_reraises_out_of_sync_when_describe_conflict_fails(self, mocker: MockerFixture) -> None:
        mocker.patch.object(RedisEncryptedSession, "describe_conflict", side_effect=RuntimeError("boom"))

        def change(sess: EduidSession) -> None:
            sess.idp.sso_cookie_val = "mine"

        exc, count_spy, _response, _commit_spy, _db, _cookie = self._lose_conflict(mocker, change)
        assert isinstance(exc, SessionOutOfSync)
        count_spy.assert_any_call("session_out_of_sync_error")

    def test_save_session_custom_safe_paths_swallow_otherwise_fatal_path(self, mocker: MockerFixture) -> None:
        def change(sess: EduidSession) -> None:
            sess.common.eppn = "hrrebwn7"

        # With the default config this change is fatal, see test_save_session_reraises_out_of_sync_for_common_eppn
        mocker.patch.object(self.app.conf, "session_safe_to_lose_paths", ["common"])
        exc, count_spy, _response, _commit_spy, db, _cookie = self._lose_conflict(mocker, change)
        assert exc is None
        count_spy.assert_any_call("session_state_lost")
        assert "common" not in db.to_dict()

    def test_save_session_empty_safe_paths_reraises_even_for_allowlisted_paths(self, mocker: MockerFixture) -> None:
        mocker.patch.object(self.app.conf, "session_safe_to_lose_paths", [])

        def change(sess: EduidSession) -> None:
            sess.idp.pending_requests[RequestRef("test-ref")].used = True
            sess.idp.sso_cookie_val = "mine"

        exc, count_spy, _response, _commit_spy, db, _cookie = self._lose_conflict(mocker, change)
        assert isinstance(exc, SessionOutOfSync)
        assert mocker.call("session_state_lost") not in count_spy.call_args_list
        self._assert_lost_not_persisted(db)

    def test_timestamp_not_bumped_when_unchanged(self, mocker: MockerFixture) -> None:
        cookie_val = self._new_cookie()
        factory = self.app.session_interface
        with self.app.test_request_context(headers=self._headers(cookie_val)):
            sess = factory.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            ts = sess.idp.ts
            assert sess.idp.sso_cookie_val == "first"
            sess._serialize_namespaces()
            assert sess.idp.ts == ts
            assert sess.modified is False

            commit_spy = mocker.spy(sess._session, "commit")
            factory.save_session(self.app, sess, Response())
            commit_spy.assert_not_called()

    def test_timestamp_bumped_on_change_after_reload(self) -> None:
        cookie_val = self._new_cookie()
        factory = self.app.session_interface
        with self.app.test_request_context(headers=self._headers(cookie_val)):
            sess = factory.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            ts = sess.idp.ts
            sess.idp.sso_cookie_val = "changed"
            sess._serialize_namespaces()
            assert sess.idp.ts > ts
            assert sess.modified is True

    def test_backend_ttl_refreshed_without_changes(self) -> None:
        cookie_val = self._new_cookie()
        factory = self.app.session_interface
        with self.app.test_request_context(headers=self._headers(cookie_val)):
            sess = factory.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            key = sess._session.db_key
            conn = sess._session.conn
            conn.expire(key, 5)
            raw_before = conn.get(key)
            time.sleep(0.01)
            factory.save_session(self.app, sess, Response())
            ttl = cast(int, conn.ttl(key))
            assert ttl > 5
            assert conn.get(key) == raw_before

    def _save_unmodified_after(
        self, mocker: MockerFixture, other_writer: Callable[[RedisEncryptedSession], None] | None
    ) -> tuple[Exception | None, Any, EduidSession, str]:
        """Open a session, change nothing, let another writer act, then run save_session (no-write path)"""
        cookie_val = self._new_cookie()
        factory = self.app.session_interface
        assert isinstance(factory, SessionFactory)
        with self.app.test_request_context(headers=self._headers(cookie_val)):
            sess = factory.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            if other_writer is not None:
                other_writer(factory.manager.get_session(meta=sess.meta, new=False))
            count_spy = mocker.spy(self.app.stats, "count")
            commit_spy = mocker.spy(sess._session, "commit")
            exc: Exception | None = None
            try:
                factory.save_session(self.app, sess, Response())
            except SessionOutOfSync as e:
                exc = e
            commit_spy.assert_not_called()
            return exc, count_spy, sess, cookie_val

    def test_unmodified_save_raises_when_key_deleted(self, mocker: MockerFixture) -> None:
        exc, count_spy, sess, _cookie = self._save_unmodified_after(mocker, lambda other: other.clear())
        assert isinstance(exc, SessionOutOfSync)
        count_spy.assert_any_call("session_out_of_sync_error")
        assert sess._commit_failed is True
        assert sess._session.conn.get(sess._session.db_key) is None  # EXPIRE did not recreate anything

    def test_unmodified_save_raises_when_key_recreated_with_other_data(self, mocker: MockerFixture) -> None:
        def logout_and_new_login(other: RedisEncryptedSession) -> None:
            other.clear()
            other["fresh"] = "content"
            other.commit()

        exc, count_spy, _sess, _cookie = self._save_unmodified_after(mocker, logout_and_new_login)
        assert isinstance(exc, SessionOutOfSync)
        count_spy.assert_any_call("session_out_of_sync_error")

    def test_unmodified_save_swallows_benign_sibling_change(self, mocker: MockerFixture) -> None:
        def add_key(other: RedisEncryptedSession) -> None:
            other["other"] = "writer"
            other.commit()

        exc, count_spy, _sess, _cookie = self._save_unmodified_after(mocker, add_key)
        assert exc is None
        count_spy.assert_any_call("session_out_of_sync_error")
        count_spy.assert_any_call("session_state_lost")

    def test_unmodified_save_renews_ttl_when_unchanged(self, mocker: MockerFixture) -> None:
        cookie_val = self._new_cookie()
        factory = self.app.session_interface
        with self.app.test_request_context(headers=self._headers(cookie_val)):
            sess = factory.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            conn = sess._session.conn
            conn.expire(sess._session.db_key, 5)
            factory.save_session(self.app, sess, Response())
            assert cast(int, conn.ttl(sess._session.db_key)) > 5
            assert sess._commit_failed is False


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("idp.ts", True),
        ("idp.sso_cookie_val", True),
        ("idp.pending_requests.abc.used", True),
        ("idp.pending_requests.abc", False),
        ("idp.pending_requests", False),
        ("idp.pending_requests.abc.aborted", False),
        ("idp.pending_requests.abc.credentials_used", False),
        ("idp.pending_requests.abc.credentials_used.x.ts", False),
        ("idp.pending_requests.abc.used.deeper", False),
        ("idp.pending_requests.used", False),
        ("idp.ts.deeper", False),
        ("idp", False),
        ("idp.tsx", False),
        ("xidp.ts", False),
        ("common.eppn", False),
        ("mfa_action", False),
        ("security.authn.consumed", False),
    ],
)
def test_path_matches_allowlist(path: str, expected: bool) -> None:
    patterns = SessionTestConfig.model_fields["session_safe_to_lose_paths"].default
    assert any(_path_matches(path, pattern) for pattern in patterns) is expected


DEFAULT_SAFE_TO_LOSE = ["idp.ts", "idp.sso_cookie_val", "idp.pending_requests.*.used"]


def test_default_safe_to_lose_paths() -> None:
    config = load_config(
        typ=SessionTestConfig, app_name="testing", ns="webapp", test_config={"mongo_uri": "mongodb://x"}
    )
    assert config.session_safe_to_lose_paths == DEFAULT_SAFE_TO_LOSE


@pytest.mark.parametrize("bad", ["", ".", "idp.", ".ts", "idp..ts"])
def test_invalid_safe_to_lose_path_rejected(bad: str) -> None:
    with pytest.raises(ValueError, match="empty"):
        SessionTestConfig.model_validate({"mongo_uri": "mongodb://x", "session_safe_to_lose_paths": [bad]})


def test_all_safe_to_lose() -> None:
    p = DEFAULT_SAFE_TO_LOSE
    assert _all_safe_to_lose([], p)
    assert _all_safe_to_lose(["changed idp.ts", "changed idp.pending_requests.r.used", "removed idp.sso_cookie_val"], p)
    assert not _all_safe_to_lose(["changed idp.ts", "added common.eppn"], p)
    assert not _all_safe_to_lose(["added idp.pending_requests.r"], p)
    assert not _all_safe_to_lose(["changed idp.pending_requests.r.other_field"], p)


def test_all_safe_to_lose_empty_patterns_never_swallows() -> None:
    assert not _all_safe_to_lose(["changed idp.ts"], [])
