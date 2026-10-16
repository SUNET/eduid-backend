import logging
import time
from collections.abc import Callable, Mapping
from datetime import timedelta
from typing import Any, cast

import pytest
from flask import Response, request
from pytest_mock import MockerFixture

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.config.parsers import load_config
from eduid.common.misc.timeutil import utc_now
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.common.authn.utils import no_authn_views
from eduid.webapp.common.session import session
from eduid.webapp.common.session.eduid_session import (
    EduidNamespaces,
    EduidSession,
    SessionFactory,
    _all_safe_to_lose,
    _any_matches,
    _path_matches,
)
from eduid.webapp.common.session.meta import SessionMeta
from eduid.webapp.common.session.namespaces import IdP_SAMLPendingRequest, LoginApplication, RequestRef
from eduid.webapp.common.session.redis_session import GENERATION_KEY, RedisEncryptedSession, SessionOutOfSync

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

    def _strip_generation(self, cookie_val: str) -> None:
        """Turn a stored session into a legacy one (written before the generation marker existed)"""
        factory = self.app.session_interface
        assert isinstance(factory, SessionFactory)
        meta = SessionMeta.from_cookie(cookie_val, app_secret=factory.manager.secret)
        raw = factory.manager.get_session(meta=meta, new=False)
        del raw[GENERATION_KEY]
        raw.commit()

    @staticmethod
    def _reset_keeping_content(other: RedisEncryptedSession, **idp_changes: Any) -> None:
        """
        Simulate a logout followed by a login that restores the very same key paths (e.g. retained pending
        request + CSRF token, as /logout does), changing at most the given idp fields. Only the generation
        marker (and the idp fields) differ from the loaded content.
        """
        data = other.to_dict()
        other.clear()  # new generation
        for key, value in data.items():
            if key == GENERATION_KEY:
                continue
            other[key] = {**value, **idp_changes} if key == "idp" and idp_changes else value
        other.commit()

    def _new_cookie_with_request(self, legacy: bool = False) -> tuple[str, RequestRef]:
        """Create and persist a session with an idp pending request, return its cookie value and the request ref"""
        ref = RequestRef("test-ref")
        with self.app.test_request_context():
            sess = self.app.session_interface.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            sess.idp.sso_cookie_val = "first"
            sess.idp.pending_requests[ref] = IdP_SAMLPendingRequest(request="req", binding="binding")
            sess.persist()
            cookie_val = sess.meta.cookie_val
        if legacy:
            self._strip_generation(cookie_val)
        return cookie_val, ref

    def _lose_conflict(
        self,
        mocker: MockerFixture,
        change: Callable[[EduidSession], None],
        other_writer: Callable[[RedisEncryptedSession], None] | None = None,
        legacy: bool = False,
    ) -> tuple[Any, Any, Response, Any, Any, str]:
        """
        Open a session, apply `change`, let another writer commit first, and run save_session.

        The other writer adds the key 'other' unless `other_writer` is given. It must commit itself.
        With `legacy` the stored session has no generation marker.

        :returns: (outcome exception or None, count spy, response, commit spy, session, cookie_val)
        """
        cookie_val, ref = self._new_cookie_with_request(legacy=legacy)
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
            # ... and the conflict is reported exactly once
            assert count_spy.call_args_list.count(mocker.call("session_out_of_sync_error")) == 1
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

    def test_explicit_persist_conflict_is_reported_once_by_save_session(
        self, mocker: MockerFixture, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A view calling persist() itself must still get the conflict counted and described"""
        cookie_val, _ref = self._new_cookie_with_request()
        factory = self.app.session_interface
        assert isinstance(factory, SessionFactory)
        with self.app.test_request_context(headers=self._headers(cookie_val)):
            sess = factory.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            sess.idp.pending_requests[RequestRef("test-ref")].used = True

            other = factory.manager.get_session(meta=sess.meta, new=False)
            other["other"] = "writer"
            other.commit()

            count_spy = mocker.spy(self.app.stats, "count")
            conflict_spy = mocker.spy(SessionFactory, "_log_conflict")
            commit_spy = mocker.spy(sess._session, "commit")

            # The view's explicit persist() fails and the exception propagates out of the view
            with pytest.raises(SessionOutOfSync):
                sess.persist()
            assert count_spy.call_args_list == []

            # Error response finalization
            with caplog.at_level(logging.ERROR):
                response = Response()
                factory.save_session(self.app, sess, response)
            assert count_spy.call_args_list == [mocker.call("session_out_of_sync_error")]
            conflict_spy.assert_called_once()
            assert "changed by other writer" in caplog.text
            assert response.headers.getlist("Set-Cookie")

            # Another save in the same request neither retries nor reports again
            factory.save_session(self.app, sess, Response())
            assert count_spy.call_args_list == [mocker.call("session_out_of_sync_error")]
            conflict_spy.assert_called_once()
            assert commit_spy.call_count == 1
            assert mocker.call("session_state_lost") not in count_spy.call_args_list

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
        assert set(db.to_dict()) == {GENERATION_KEY}  # empty (new) session

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
        assert set(db.to_dict()) == {"fresh", GENERATION_KEY}

    def test_save_session_reraises_when_reset_changed_only_idp_ts(self, mocker: MockerFixture) -> None:
        """A reset that restores the same paths and only touches idp.ts is caught by the generation marker"""
        ts = utc_now() + timedelta(seconds=5)
        exc, count_spy, _response, _commit_spy, db, _cookie = self._lose_conflict(
            mocker,
            self._allowlisted_change,
            other_writer=lambda other: self._reset_keeping_content(other, ts=ts.isoformat()),
        )
        assert isinstance(exc, SessionOutOfSync)
        assert mocker.call("session_state_lost") not in count_spy.call_args_list
        assert db.to_dict()["idp"]["sso_cookie_val"] == "first"  # our change was not persisted
        assert db.to_dict()["idp"]["ts"] == ts.isoformat()

    def test_save_session_swallows_benign_write_within_same_generation(self, mocker: MockerFixture) -> None:
        generations: list[str | None] = []

        def benign(other: RedisEncryptedSession) -> None:
            generations.append(other.generation)
            other["other"] = "writer"
            other.commit()

        exc, count_spy, _response, _commit_spy, db, _cookie = self._lose_conflict(
            mocker, self._allowlisted_change, other_writer=benign
        )
        assert exc is None
        count_spy.assert_any_call("session_state_lost")
        assert generations[0] is not None
        assert db.generation == generations[0]

    def test_legacy_session_benign_write_still_swallowed(self, mocker: MockerFixture) -> None:
        exc, count_spy, _response, _commit_spy, db, _cookie = self._lose_conflict(
            mocker, self._allowlisted_change, legacy=True
        )
        assert exc is None
        count_spy.assert_any_call("session_state_lost")
        assert db.generation is None

    def test_legacy_session_reset_by_other_writer_is_fatal(self, mocker: MockerFixture) -> None:
        exc, count_spy, _response, _commit_spy, db, _cookie = self._lose_conflict(
            mocker,
            self._allowlisted_change,
            other_writer=self._reset_keeping_content,
            legacy=True,
        )
        assert isinstance(exc, SessionOutOfSync)
        assert mocker.call("session_state_lost") not in count_spy.call_args_list
        assert db.generation is not None

    def test_new_session_gets_generation_and_reads_do_not_modify(self) -> None:
        factory = self.app.session_interface
        assert isinstance(factory, SessionFactory)
        with self.app.test_request_context():
            sess = factory.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            assert sess.new is True
            first = sess._session.generation
            assert first
            _ = (sess.idp, sess.common, sess.signup)  # plain reads
            sess._serialize_namespaces()
            sess.idp.sso_cookie_val = "x"
            sess.persist()
            cookie_val = sess.meta.cookie_val

        with self.app.test_request_context(headers=self._headers(cookie_val)):
            sess = factory.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            assert sess._session.generation == first
            _ = (sess.idp, sess.common)
            sess._serialize_namespaces()
            assert sess.modified is False
            sess.reset()
            assert sess.modified is True
            assert sess._session.generation
            assert sess._session.generation != first
            sess.persist()

        with self.app.test_request_context(headers=self._headers(cookie_val)):
            sess = factory.open_session(self.app, request)
            assert sess._session.generation not in (None, first)

    def test_legacy_session_not_given_generation_by_reads(self) -> None:
        cookie_val, _ref = self._new_cookie_with_request(legacy=True)
        factory = self.app.session_interface
        assert isinstance(factory, SessionFactory)
        with self.app.test_request_context(headers=self._headers(cookie_val)):
            sess = factory.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            assert sess._session.generation is None
            _ = sess.idp
            sess._serialize_namespaces()
            assert sess.modified is False
            factory.save_session(self.app, sess, Response())
            assert sess._session.generation is None
            sess.reset()  # a reset assigns one
            assert sess._session.to_dict()[GENERATION_KEY]

    def test_generation_not_in_namespaces(self) -> None:
        cookie_val, _ref = self._new_cookie_with_request()
        factory = self.app.session_interface
        assert isinstance(factory, SessionFactory)
        with self.app.test_request_context(headers=self._headers(cookie_val)):
            sess = factory.open_session(self.app, request)
            assert isinstance(sess, EduidSession)
            assert GENERATION_KEY in sess._session.to_dict()
            for name in EduidNamespaces.model_fields:
                assert GENERATION_KEY not in str(getattr(sess._namespaces, name) or "")
            assert GENERATION_KEY not in sess.idp.to_dict()

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

    def _abort_by_other_writer(self, other: RedisEncryptedSession) -> None:
        data = other.to_dict()
        idp = dict(data["idp"])
        pending = {k: dict(v) for k, v in idp["pending_requests"].items()}
        pending[self._ref]["aborted"] = True
        idp["pending_requests"] = pending
        other["idp"] = idp
        other.commit()

    def test_save_session_reraises_when_other_writer_aborted_pending_request(self, mocker: MockerFixture) -> None:
        exc, count_spy, _response, _commit_spy, db, _cookie = self._lose_conflict(
            mocker, self._allowlisted_change, other_writer=self._abort_by_other_writer
        )
        assert isinstance(exc, SessionOutOfSync)
        count_spy.assert_any_call("session_out_of_sync_error")
        assert mocker.call("session_state_lost") not in count_spy.call_args_list
        assert db.to_dict()["idp"]["pending_requests"][self._ref]["aborted"] is True
        assert db.to_dict()["idp"]["pending_requests"][self._ref]["used"] is False

    def test_save_session_swallows_unrelated_other_writer_change(self, mocker: MockerFixture) -> None:
        def other_writer(other: RedisEncryptedSession) -> None:
            data = other.to_dict()
            idp = dict(data["idp"])
            pending = {k: dict(v) for k, v in idp["pending_requests"].items()}
            pending[self._ref]["template_show_msg"] = True
            idp["pending_requests"] = pending
            other["idp"] = idp
            other.commit()

        exc, count_spy, _response, _commit_spy, _db, _cookie = self._lose_conflict(
            mocker, self._allowlisted_change, other_writer=other_writer
        )
        assert exc is None
        count_spy.assert_any_call("session_state_lost")

    def test_save_session_custom_fatal_other_writer_paths(self, mocker: MockerFixture) -> None:
        # default rule does not cover 'other', so this is swallowed by default (see the swallow tests above)
        mocker.patch.object(self.app.conf, "session_fatal_other_writer_paths", ["other"])
        exc, count_spy, _response, _commit_spy, _db, _cookie = self._lose_conflict(mocker, self._allowlisted_change)
        assert isinstance(exc, SessionOutOfSync)
        assert mocker.call("session_state_lost") not in count_spy.call_args_list

    def test_save_session_empty_fatal_other_writer_paths_disables_rule(self, mocker: MockerFixture) -> None:
        mocker.patch.object(self.app.conf, "session_fatal_other_writer_paths", [])
        exc, count_spy, _response, _commit_spy, _db, _cookie = self._lose_conflict(
            mocker, self._allowlisted_change, other_writer=self._abort_by_other_writer
        )
        assert exc is None
        count_spy.assert_any_call("session_state_lost")

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

    def test_unmodified_save_raises_when_only_generation_changed(self, mocker: MockerFixture) -> None:
        """The no-write renew_ttl path compares the stored blob, so a reset with identical content is caught"""
        exc, count_spy, sess, _cookie = self._save_unmodified_after(mocker, self._reset_keeping_content)
        assert isinstance(exc, SessionOutOfSync)
        count_spy.assert_any_call("session_out_of_sync_error")
        assert mocker.call("session_state_lost") not in count_spy.call_args_list
        assert sess._commit_failed is True

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
    # no net diff (a key changed and restored) must not be swallowed when the setting is disabled
    assert not _all_safe_to_lose([], [])


def test_default_fatal_other_writer_paths() -> None:
    config = load_config(
        typ=SessionTestConfig, app_name="testing", ns="webapp", test_config={"mongo_uri": "mongodb://x"}
    )
    assert config.session_fatal_other_writer_paths == ["idp.pending_requests.*.aborted"]


@pytest.mark.parametrize("bad", ["", ".", "idp.", ".ts", "idp..ts"])
def test_invalid_fatal_other_writer_path_rejected(bad: str) -> None:
    with pytest.raises(ValueError, match="session_fatal_other_writer_paths"):
        SessionTestConfig.model_validate({"mongo_uri": "mongodb://x", "session_fatal_other_writer_paths": [bad]})


def test_any_matches() -> None:
    p = ["idp.pending_requests.*.aborted"]
    assert _any_matches(["changed idp.pending_requests.r.aborted"], p)
    assert _any_matches(["changed idp.ts", "added idp.pending_requests.r.aborted"], p)
    assert _any_matches(["removed idp.pending_requests.r.aborted"], p)
    assert not _any_matches(["changed idp.ts", "added idp.pending_requests.r"], p)
    assert not _any_matches([], p)
    assert not _any_matches(["changed idp.pending_requests.r.aborted"], [])
