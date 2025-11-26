import logging
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from eduid.common.config.base import FrontendAction
from eduid.common.config.parsers import load_config
from eduid.common.testing_base import normalised_data
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.session import EduidSession
from eduid.webapp.common.session.eduid_session import SessionFactory
from eduid.webapp.common.session.meta import SessionMeta
from eduid.webapp.common.session.namespaces import AuthnRequestRef, SP_AuthnRequest
from eduid.webapp.common.session.tests.test_eduid_session import SessionTestApp, SessionTestConfig

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TestNameSpaceBase(EduidAPITestCase):
    app: SessionTestApp

    def load_app(self, config: Mapping[str, Any]) -> SessionTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        logger.debug("Starting SessionTestApp")
        config = load_config(typ=SessionTestConfig, app_name="testing", ns="webapp", test_config=config)
        app = SessionTestApp(config)
        logger.debug("Started SessionTestApp")
        app.session_interface = SessionFactory(app.conf)
        return app

    def get_session(self, meta: SessionMeta, new: bool = True) -> EduidSession:
        assert isinstance(self.app.session_interface, SessionFactory)
        base_session = self.app.session_interface.manager.get_session(meta=meta, new=new)
        return EduidSession(app=self.app, meta=meta, base_session=base_session, new=new)


class TestNamespace(TestNameSpaceBase):
    def test_to_dict_from_dict(self) -> None:
        _meta = SessionMeta.new(app_secret="secret")
        session = self.get_session(meta=_meta)
        assert session.idp.sso_cookie_val is None

        session.idp.sso_cookie_val = "abc"
        session.signup.email.verification_code = "test"

        session._serialize_namespaces()
        out = session._session.to_dict()
        normalised_out = normalised_data(out, exclude_keys=["ts"])

        assert normalised_out == {
            "signup": {
                "user_created": False,
                "email": {"completed": False, "verification_code": "test", "bad_attempts": 0},
                "invite": {"initiated_signup": False, "completed": False},
                "name": {},
                "tou": {"completed": False},
                "captcha": {"bad_attempts": 0, "completed": False},
                "credentials": {"completed": False},
            },
            "idp": {"sso_cookie_val": "abc", "pending_requests": {}},
        }, f"Actual result: {normalised_out}"

        session.persist()

        # Validate that the session can be loaded again
        loaded_session = self.get_session(meta=_meta, new=False)
        # ...and that it serialises to the same data again
        assert normalised_out == normalised_data(loaded_session._session.to_dict(), exclude_keys=["ts"]), (
            f"Actual result: {normalised_out}"
        )

    def test_to_dict_from_dict_with_timestamp(self) -> None:
        _meta = SessionMeta.new(app_secret="secret")
        first = self.get_session(meta=_meta)

        assert first.idp.sso_cookie_val is None

        first.idp.sso_cookie_val = "abc"
        first.idp.ts = datetime.fromisoformat("2020-09-13T12:26:40+00:00")

        first._serialize_namespaces()
        out = first._session.to_dict()

        assert out == {
            "idp": {"sso_cookie_val": "abc", "pending_requests": {}, "ts": "2020-09-13T12:26:40Z"},
        }

        first.persist()

        # Validate that the session can be loaded again
        second = self.get_session(meta=_meta, new=False)
        # ...and that it serialises to the same data that was persisted
        assert normalised_data(out, exclude_keys=["ts"]) == normalised_data(
            second._session.to_dict(), exclude_keys=["ts"]
        )

        assert second.idp.sso_cookie_val == first.idp.sso_cookie_val
        assert second.idp.ts == first.idp.ts

    def test_clear_namespace(self) -> None:
        _meta = SessionMeta.new(app_secret="secret")
        first = self.get_session(meta=_meta)
        first.signup.email.address = "test@example.com"
        first.signup.email.verification_code = "123456"
        first.persist()
        # load session again and clear it
        second = self.get_session(meta=_meta, new=False)
        assert second.signup.email.address == "test@example.com"
        assert second.signup.email.verification_code == "123456"
        second.signup.clear()
        second.signup.email.address = "test@example.com"
        second.persist()
        # load session one more time and make sure verification_code is empty
        third = self.get_session(meta=_meta, new=False)
        assert third.signup.email.address == "test@example.com"
        assert third.signup.email.verification_code is None


class TestAuthnNamespace(TestNameSpaceBase):
    def test_sp_authns_cleanup(self) -> None:
        _meta = SessionMeta.new(app_secret="secret")
        sess = self.get_session(meta=_meta)
        for i in range(15):
            sess.authn.sp.authns[AuthnRequestRef(str(i))] = SP_AuthnRequest(
                frontend_action=FrontendAction.LOGIN, finish_url="some_url"
            )
        assert len(sess.authn.sp.authns) == 15, f"Expected 15 authns got {len(sess.authn.sp.authns)}"
        sess.persist()
        # load the session again

        sess = self.get_session(meta=_meta, new=False)
        assert len(sess.authn.sp.authns) == 10, f"Expected 10 authns got {len(sess.authn.sp.authns)}"

    def test_sp_authns_overwrite(self) -> None:
        _meta = SessionMeta.new(app_secret="secret")
        sess1 = self.get_session(meta=_meta)
        for i in range(5):
            sess1.authn.sp.authns[AuthnRequestRef(str(i))] = SP_AuthnRequest(
                frontend_action=FrontendAction.LOGIN, finish_url="some_url"
            )
        sess1.persist()
        # load the session again
        sess2 = self.get_session(meta=_meta, new=False)
        # this next read should not change anything in the session
        sess2.authn.sp.get_latest_authn()
        sess2.persist()
        assert sess1._session._raw_data == sess2._session._raw_data
