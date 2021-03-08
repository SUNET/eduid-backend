import logging
from datetime import datetime
from typing import Any, Mapping

from eduid_common.api.testing import EduidAPITestCase
from eduid_common.config.parsers import load_config
from eduid_common.session import EduidSession
from eduid_common.session.eduid_session import SessionFactory
from eduid_common.session.meta import SessionMeta
from eduid_common.session.tests.test_eduid_session import SessionTestApp, SessionTestConfig

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TestIdPNamespace(EduidAPITestCase):

    app: SessionTestApp

    def load_app(self, test_config: Mapping[str, Any]) -> SessionTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        logger.debug('Starting SessionTestApp')
        config = load_config(typ=SessionTestConfig, app_name='testing', ns='webapp', test_config=test_config)
        app = SessionTestApp(config)
        logger.debug('Started SessionTestApp')
        app.session_interface = SessionFactory(app.conf)
        return app

    def test_to_dict_from_dict(self):
        _meta = SessionMeta.new(app_secret='secret')
        base_session = self.app.session_interface.manager.get_session(meta=_meta, new=True)
        session = EduidSession(app=self.app, meta=_meta, base_session=base_session, new=True)

        assert session.idp.sso_cookie_val is None

        session.idp.sso_cookie_val = 'abc'
        session.signup.email_verification_code = 'test'

        session._serialize_namespaces()
        out = session._session.to_dict()

        assert out == {
            '_idp': {'sso_cookie_val': 'abc', 'ts': None},
            '_signup': {'email_verification_code': 'test', 'ts': None},
        }

        session.persist()

        # Validate that the session can be loaded again
        loaded_session = self.app.session_interface.manager.get_session(meta=_meta, new=False)
        # ...and that it serialises to the same data that was persisted
        assert loaded_session.to_dict() == out

    def test_to_dict_from_dict_with_timestamp(self):
        _meta = SessionMeta.new(app_secret='secret')
        base_session = self.app.session_interface.manager.get_session(meta=_meta, new=True)
        first = EduidSession(app=self.app, meta=_meta, base_session=base_session, new=True)

        assert first.idp.sso_cookie_val is None

        first.idp.sso_cookie_val = 'abc'
        first.idp.ts = datetime.fromisoformat('2020-09-13T12:26:40+00:00')

        first._serialize_namespaces()
        out = first._session.to_dict()

        assert out == {
            '_idp': {'sso_cookie_val': 'abc', 'ts': '1600000000'},
        }

        first.persist()

        # Validate that the session can be loaded again
        base_session = self.app.session_interface.manager.get_session(meta=_meta, new=False)
        second = EduidSession(self.app, _meta, base_session, new=False)
        # ...and that it serialises to the same data that was persisted
        assert second._session.to_dict() == out

        assert second.idp.sso_cookie_val == first.idp.sso_cookie_val
        assert second.idp.ts == first.idp.ts
