import logging
from datetime import datetime
from typing import Any, Mapping

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


class TestIdPNamespace(EduidAPITestCase):
    app: SessionTestApp

    def load_app(self, test_config: Mapping[str, Any]) -> SessionTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        logger.debug("Starting SessionTestApp")
        config = load_config(typ=SessionTestConfig, app_name="testing", ns="webapp", test_config=test_config)
        app = SessionTestApp(config)
        logger.debug("Started SessionTestApp")
        app.session_interface = SessionFactory(app.conf)
        return app

    def test_to_dict_from_dict(self):
        _meta = SessionMeta.new(app_secret="secret")
        base_session = self.app.session_interface.manager.get_session(meta=_meta, new=True)
        session = EduidSession(app=self.app, meta=_meta, base_session=base_session, new=True)

        assert session.idp.sso_cookie_val is None

        session.idp.sso_cookie_val = "abc"
        session.signup.email.verification_code = "test"

        session._serialize_namespaces()
        out = session._session.to_dict()

        assert normalised_data(out, replace_datetime="now") == {
            "signup": {
                "ts": "now",
                "user_created": False,
                "email": {"completed": False, "verification_code": "test", "bad_attempts": 0},
                "invite": {"initiated_signup": False, "completed": False},
                "name": {},
                "tou": {"completed": False},
                "captcha": {"bad_attempts": 0, "completed": False},
                "credentials": {"completed": False},
            },
            "idp": {"ts": "now", "sso_cookie_val": "abc", "pending_requests": {}},
        }, f"Actual result: {normalised_data(out, replace_datetime='now')}"

        session.persist()

        # Validate that the session can be loaded again
        loaded_session = self.app.session_interface.manager.get_session(meta=_meta, new=False)
        # loaded_session is raw data from the storage backend, it won't have timestamps deserialised into datetimes
        # (done by pydantic when loading the data into the EduidSession), so in order to expect the same serialisation
        # again we need to do that here
        loaded_session["idp"]["ts"] = datetime.fromisoformat(loaded_session["idp"]["ts"])
        loaded_session["signup"]["ts"] = datetime.fromisoformat(loaded_session["signup"]["ts"])
        # ...and that it serialises to the same data again
        assert loaded_session.to_dict() == out

    def test_to_dict_from_dict_with_timestamp(self):
        _meta = SessionMeta.new(app_secret="secret")
        base_session = self.app.session_interface.manager.get_session(meta=_meta, new=True)
        first = EduidSession(app=self.app, meta=_meta, base_session=base_session, new=True)

        assert first.idp.sso_cookie_val is None

        first.idp.sso_cookie_val = "abc"
        first.idp.ts = datetime.fromisoformat("2020-09-13T12:26:40+00:00")

        first._serialize_namespaces()
        out = first._session.to_dict()

        assert out == {
            "idp": {"sso_cookie_val": "abc", "pending_requests": {}, "ts": first.idp.ts},
        }

        first.persist()

        # Validate that the session can be loaded again
        base_session = self.app.session_interface.manager.get_session(meta=_meta, new=False)
        second = EduidSession(self.app, _meta, base_session, new=False)
        # loaded_session is raw data from the storage backend, it won't have timestamps deserialised into datetimes
        # (done by pydantic when loading the data into the EduidSession), so in order to expect the same serialisation
        # again we need to do that here
        second["idp"]["ts"] = datetime.fromisoformat(second["idp"]["ts"])
        # ...and that it serialises to the same data that was persisted
        assert second._session.to_dict() == out

        assert second.idp.sso_cookie_val == first.idp.sso_cookie_val
        assert second.idp.ts == first.idp.ts


class TestAuthnNamespace(EduidAPITestCase):
    app: SessionTestApp

    def load_app(self, test_config: Mapping[str, Any]) -> SessionTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        logger.debug("Starting SessionTestApp")
        config = load_config(typ=SessionTestConfig, app_name="testing", ns="webapp", test_config=test_config)
        app = SessionTestApp(config)
        logger.debug("Started SessionTestApp")
        app.session_interface = SessionFactory(app.conf)
        return app

    def test_sp_authns_cleanup(self):
        _meta = SessionMeta.new(app_secret="secret")
        base_session = self.app.session_interface.manager.get_session(meta=_meta, new=True)
        sess = EduidSession(app=self.app, meta=_meta, base_session=base_session, new=True)
        for i in range(15):
            sess.authn.sp.authns[AuthnRequestRef(str(i))] = SP_AuthnRequest(
                frontend_action=FrontendAction.LOGIN, finish_url="some_url"
            )
        assert len(sess.authn.sp.authns) == 15, f"Expected 15 authns got {len(sess.authn.sp.authns)}"
        sess.persist()
        # load the session again
        base_session = self.app.session_interface.manager.get_session(meta=_meta, new=False)
        sess = EduidSession(self.app, _meta, base_session, new=False)
        assert len(sess.authn.sp.authns) == 10, f"Expected 10 authns got {len(sess.authn.sp.authns)}"
