# -*- coding: utf-8 -*-

from typing import Any, Dict, List, Optional

from eduid_common.api.testing import EduidAPITestCase
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_common.authn.utils import no_authn_views
from eduid_common.config.base import FlaskConfig
from eduid_common.session import session
from eduid_common.session.namespaces import LoginApplication

__author__ = 'lundberg'


class SessionTestApp(AuthnBaseApp):
    def __init__(self, name: str, config: Dict[str, Any], **kwargs):
        self.config = FlaskConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)


def session_init_app(name, config):
    app = SessionTestApp(name, config, init_central_userdb=False)
    app = no_authn_views(app, ['/unauthenticated'])

    @app.route('/authenticated')
    def authenticated():
        session['authenticated_request'] = True
        return 'Hello, World!'

    @app.route('/unauthenticated')
    def unauthenticated():
        session['unauthenticated_request'] = True
        return 'Hello, World!'

    @app.route('/return-session-key-test')
    def return_session_key_test():
        return session['test']

    @app.route('/common')
    def common():
        session.common.eppn = 'hubba-bubba'
        session.common.is_logged_in = True
        session.common.login_source = LoginApplication['authn']
        return 'Hello, World!'

    @app.route('/mfa-action')
    def mfa_action():
        session.mfa_action.success = True
        session.mfa_action.issuer = 'https://issuer-entity-id.example.com'
        session.mfa_action.authn_instant = '2019-03-21T16:26:17Z'
        session.mfa_action.authn_context = 'http://id.elegnamnden.se/loa/1.0/loa3'
        return 'Hello, World!'

    @app.route('/reset-password')
    def reset_password():
        session.reset_password.generated_password_hash = 'password-hash'
        return 'Hello, World!'

    @app.route('/signup')
    def signup():
        session.signup.email_verification_code = 'email-verification-code'
        return 'Hello, World!'

    return app


class EduidSessionTests(EduidAPITestCase):
    def setUp(
        self,
        users: Optional[List[str]] = None,
        copy_user_to_private: bool = False,
        am_settings: Optional[Dict[str, Any]] = None,
    ):
        self.test_user_eppn = 'hubba-bubba'
        super().setUp(users=users, copy_user_to_private=copy_user_to_private, am_settings=am_settings)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return session_init_app('testing', config)

    def update_config(self, config):
        config.update(
            {'debug': True, 'log_level': 'DEBUG', 'no_authn_urls': [],}
        )
        return config

    def test_session_authenticated(self):
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/authenticated')
            self.assertEqual(response.status_code, 200)
            with browser.session_transaction() as sess:
                self.assertTrue(sess['authenticated_request'])

    def test_session_unauthenticated(self):
        with self.browser as browser:
            response = browser.get('/authenticated')
            self.assertEqual(response.status_code, 302)

            response = browser.get('/unauthenticated')
            self.assertEqual(response.status_code, 200)
            with browser.session_transaction() as sess:
                self.assertTrue(sess['unauthenticated_request'])

    def test_session_transaction(self):
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            with browser.session_transaction() as sess:
                sess['test'] = 'my session value'
            response = browser.get('/return-session-key-test')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode('utf-8'), 'my session value')

    def test_request_context_session(self):
        with self.app.test_request_context('/return-session-key-test', method='GET'):
            session['test'] = 'another session value'
            session.persist()  # Explicit session.persist is needed when working within a test_request_context
            response = self.app.dispatch_request()
            self.assertEqual(response, 'another session value')

    def test_session_common(self):
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/common')
            self.assertEqual(response.status_code, 200)
            with browser.session_transaction() as sess:
                self.assertTrue(sess.common.is_logged_in)
                self.assertEqual(sess.common.login_source, LoginApplication('authn'))
                self.assertEqual(sess.common.eppn, self.test_user_eppn)

    def test_session_mfa_action(self):
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/mfa-action')
            self.assertEqual(response.status_code, 200)
            with browser.session_transaction() as sess:
                self.assertTrue(sess.mfa_action.success)
                self.assertEqual(sess.mfa_action.issuer, 'https://issuer-entity-id.example.com')
                self.assertEqual(sess.mfa_action.authn_instant, '2019-03-21T16:26:17Z')
                self.assertEqual(sess.mfa_action.authn_context, 'http://id.elegnamnden.se/loa/1.0/loa3')

    def test_session_reset_password(self):
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/reset-password')
            self.assertEqual(response.status_code, 200)
            with browser.session_transaction() as sess:
                self.assertEqual(sess.reset_password.generated_password_hash, 'password-hash')

    def test_session_signup(self):
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/signup')
            self.assertEqual(response.status_code, 200)
            with browser.session_transaction() as sess:
                self.assertEqual(sess.signup.email_verification_code, 'email-verification-code')

    def test_clear_session_mfa_action(self):
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/mfa-action')
            self.assertEqual(response.status_code, 200)
            with browser.session_transaction() as sess:
                self.assertTrue(sess.mfa_action.success)
                self.assertEqual(sess.mfa_action.issuer, 'https://issuer-entity-id.example.com')
                self.assertEqual(sess.mfa_action.authn_instant, '2019-03-21T16:26:17Z')
                self.assertEqual(sess.mfa_action.authn_context, 'http://id.elegnamnden.se/loa/1.0/loa3')
                del sess.mfa_action

            with browser.session_transaction() as sess:
                self.assertFalse(sess.mfa_action.success)
                self.assertIsNone(sess.mfa_action.issuer)
                self.assertIsNone(sess.mfa_action.authn_instant)
                self.assertIsNone(sess.mfa_action.authn_context)
