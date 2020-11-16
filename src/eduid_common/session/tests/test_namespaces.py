import logging
import unittest

from eduid_common.api.testing import EduidAPITestCase
from eduid_common.session import EduidSession
from eduid_common.session.eduid_session import SessionFactory
from eduid_common.session.meta import SessionMeta
from eduid_common.session.redis_session import RedisEncryptedSession
from eduid_common.session.tests.test_eduid_session import SessionTestApp

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TestIdPNamespace(EduidAPITestCase):
    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        logger.debug('Starting SessionTestApp')
        app = SessionTestApp('testing', config)
        logger.debug('Started SessionTestApp')
        app.session_interface = SessionFactory(app.config)
        return app

    def test_to_dict_from_dict(self):

        # _config = {'secret_key': 'testing'}
        # app = SessionTestApp(name='namespace-tests', config=_config)
        meta = SessionMeta.new(app_secret='secret')
        base_session = self.app.session_interface.manager.get_session(meta=meta, new=True)
        session = EduidSession(app=self.app, meta=meta, base_session=base_session, new=True)

        assert session.idp.sso_cookie_val is None

        session.idp.sso_cookie_val = 'abc'
        session.signup.email_verification_code = 'test'

        session._serialize_namespaces()
        out = session._session.to_dict()

        assert out == {'_idp': {'sso_cookie_val': 'abc', 'ts': None},
                       '_signup': {'email_verification_code': 'test', 'ts': None}}

        session.persist()

        # Validate that the session can be loaded again
        loaded_session = self.app.session_interface.manager.get_session(meta=meta, new=False)
        # ...and that it serialises to the same data that was persisted
        assert loaded_session.to_dict() == out
