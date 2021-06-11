#
# Copyright (c) 2016 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

import base64
import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Callable, Dict, Mapping

from flask import Blueprint
from saml2.s_utils import deflate_and_base64_encode
from six.moves.urllib_parse import quote_plus
from werkzeug.exceptions import NotFound
from werkzeug.http import dump_cookie

from eduid.common.config.parsers import load_config
from eduid.common.misc.timeutil import utc_now
from eduid.webapp.authn.app import AuthnApp, authn_init_app
from eduid.webapp.authn.settings.common import AuthnConfig
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.cache import OutstandingQueriesCache
from eduid.webapp.common.authn.eduid_saml2 import get_authn_request
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.common.authn.tests.responses import auth_response, logout_request, logout_response
from eduid.webapp.common.authn.utils import get_location, no_authn_views
from eduid.webapp.common.session import session

logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


class AuthnAPITestBase(EduidAPITestCase):
    """ Test cases for the real eduid-authn app """

    app: AuthnApp

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        saml_config = os.path.join(HERE, 'saml2_settings.py')
        config.update(
            {
                'safe_relay_domain': 'test.localhost',
                'saml2_login_redirect_url': '/',
                'saml2_logout_redirect_url': '/logged-out',
                'saml2_settings_module': saml_config,
                'saml2_strip_saml_user_suffix': '@test.eduid.se',
                'signup_authn_failure_redirect_url': 'http://test.localhost/failure',
                'signup_authn_success_redirect_url': 'http://test.localhost/success',
            }
        )
        return config

    def load_app(self, test_config: Mapping[str, Any]) -> AuthnApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return authn_init_app(test_config=test_config)

    def add_outstanding_query(self, came_from: str) -> str:
        """
        Add a SAML2 authentication query to the queries cache.
        To be used before accessing the assertion consumer service.

        :param came_from: url to redirect back the client
                          after finishing with the authn service.

        :return: the session token corresponding to the query
        """
        with self.app.test_request_context('/login'):
            self.app.dispatch_request()
            oq_cache = OutstandingQueriesCache(session.authn.sp.pysaml2_dicts)
            cookie_val = session.meta.cookie_val
            oq_cache.set(cookie_val, came_from)
            session.persist()  # Explicit session.persist is needed when working within a test_request_context
            return cookie_val

    def login(self, eppn: str, came_from: str) -> str:
        """
        Add a SAML2 authentication query to the queries cache,
        build a cookie with a session id corresponding to the added query,
        build a SAML2 authn response for the added query,
        and send both to the assertion consumer service,
        so that the user is logged in (the session corresponding to the cookie
        has her eppn).
        This method returns the cookie that has to be sent with any
        subsequent request that needs to be authenticated.

        :param eppn: the eppn of the user to be logged in
        :param came_from: url to redirect back the client
                          after finishing with the authn service.

        :return: the cookie corresponding to the authn session
        """
        session_id = self.add_outstanding_query(came_from)
        cookie = self.dump_session_cookie(session_id)
        saml_response = auth_response(session_id, eppn).encode('utf-8')

        with self.app.test_request_context(
            '/saml2-acs',
            method='POST',
            headers={'Cookie': cookie},
            data={'SAMLResponse': base64.b64encode(saml_response), 'RelayState': came_from},
        ):

            self.app.dispatch_request()
            session.persist()  # Explicit session.persist is needed when working within a test_request_context
            return cookie

    def authn(self, url: str, force_authn: bool = False, next_url: str = '/') -> None:
        """
        Common code for the tests that need to send an authentication request.
        This checks that the client is redirected to the idp.

        :param url: the url of the desired authentication mode.
        :param force_authn: whether to force re-authentication for an already
                            authenticated client
        :param next_url: Next url
        """
        with self.app.test_client() as c:
            resp = c.get('{}?next={}'.format(url, next_url))
            authn_req = get_location(
                get_authn_request(self.app.saml2_config, session, next_url, None, force_authn=force_authn)
            )
            idp_url = authn_req.split('?')[0]
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.location.startswith(idp_url))
            relay_state = resp.location.split('&')[-1]
            quoted_next = 'RelayState={}'.format(quote_plus(next_url))
            self.assertEqual(quoted_next, relay_state)

    def acs(self, url: str, eppn: str, check_fn: Callable, came_from: str = '/camefrom/') -> None:
        """
        common code for the tests that need to access the assertion consumer service
        and then check the side effects of this access.

        :param url: the url of the desired authentication mode.
        :param eppn: the eppn of the user to access the service
        :param check_fn: the function that checks the side effects after accessing the acs
        :param came_from: Relay state
        """
        with self.app.test_client() as c:
            resp = c.get(url)
            cookie = resp.headers['Set-Cookie']
            cookie_val = session.meta.cookie_val
            authr = auth_response(cookie_val, eppn).encode('utf-8')

        with self.app.test_request_context(
            '/saml2-acs',
            method='POST',
            headers={'Cookie': cookie},
            data={'SAMLResponse': base64.b64encode(authr), 'RelayState': came_from},
        ):

            oq_cache = OutstandingQueriesCache(session.authn.sp.pysaml2_dicts)
            oq_cache.set(cookie_val, came_from)

            resp = self.app.dispatch_request()

            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.location, came_from)
            check_fn()

    def dump_session_cookie(self, session_id: str) -> str:
        """
        Get a cookie corresponding to an authenticated session.

        :param session_id: the token for the session

        :return: the cookie
        """
        return dump_cookie(
            self.app.conf.flask.session_cookie_name,
            session_id,
            max_age=float(self.app.conf.flask.permanent_session_lifetime),
            path=self.app.conf.flask.session_cookie_path,
            domain=self.app.conf.flask.session_cookie_domain,
        )


class AuthnAPITestCase(AuthnAPITestBase):
    """
    Tests to check the different modes of authentication.
    """

    app: AuthnApp

    def setUp(self):
        super().setUp(users=['hubba-bubba', 'hubba-fooo'])

    def test_login_authn(self):
        self.authn('/login')

    def test_login_authn_good_relay_state(self):
        self.authn('/login', next_url='http://test.localhost/profile/')

    def test_login_authn_bad_relay_state(self):
        with self.assertRaises(AssertionError):
            self.authn('/login', next_url='http://bad.localhost/evil/')

    def test_chpass_authn(self):
        self.authn('/chpass', force_authn=True)

    def test_terminate_authn(self):
        self.authn('/terminate', force_authn=True)

    def test_login_assertion_consumer_service(self):
        eppn = 'hubba-bubba'

        def _check():
            assert session.common.eppn == 'hubba-bubba'

        self.acs('/login', eppn, _check)

    def test_login_assertion_consumer_service_good_relay_state(self):
        eppn = 'hubba-bubba'

        def _check():
            assert session.common.eppn == 'hubba-bubba'

        self.acs('/login', eppn, _check, came_from='http://test.localhost/profile/')

    def test_login_assertion_consumer_service_bad_relay_state(self):
        eppn = 'hubba-bubba'

        def _check():
            assert session.common.eppn == 'hubba-bubba'

        with self.assertRaises(AssertionError):
            self.acs('/login', eppn, _check, came_from='http://bad.localhost/evil/')

    def test_chpass_assertion_consumer_service(self):
        eppn = 'hubba-bubba'

        def _check():
            self.assertIn('reauthn-for-chpass', session)
            then = session['reauthn-for-chpass']
            now = int(time.time())
            self.assertTrue(now - then < 5)

        self.acs('/chpass', eppn, _check)

    def test_terminate_assertion_consumer_service(self):
        eppn = 'hubba-bubba'

        def _check():
            self.assertIn('reauthn-for-termination', session)
            then = session['reauthn-for-termination']
            now = int(time.time())
            self.assertTrue(now - then < 5)

        self.acs('/terminate', eppn, _check)

    def _signup_authn_user(self, eppn):
        timestamp = utc_now()

        with self.app.test_client() as c:
            with self.app.test_request_context('/signup-authn'):
                c.set_cookie(
                    'test.localhost', key=self.app.conf.flask.session_cookie_name, value=session.meta.cookie_val[16:]
                )
                session.common.eppn = eppn
                session.signup.ts = timestamp

                return self.app.dispatch_request()

    def test_signup_authn_new_user(self):
        eppn = 'hubba-fooo'
        resp = self._signup_authn_user(eppn)
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.location.startswith(self.app.conf.signup_authn_success_redirect_url))

    def test_signup_authn_old_user(self):
        """ A user that has verified their account should not try to use token login """
        eppn = 'hubba-bubba'
        resp = self._signup_authn_user(eppn)
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.location.startswith(self.app.conf.signup_authn_failure_redirect_url))


class AuthnTestApp(AuthnBaseApp):
    def __init__(self, config: AuthnConfig, **kwargs):
        super().__init__(config, **kwargs)
        self.conf = config


class UnAuthnAPITestCase(EduidAPITestCase):
    """ Tests for a fictitious app based on AuthnBaseApp """

    app: AuthnTestApp

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        saml_config = os.path.join(HERE, 'saml2_settings.py')
        config.update(
            {
                'saml2_login_redirect_url': '/',
                'saml2_logout_redirect_url': '/',
                'saml2_settings_module': saml_config,
                'saml2_strip_saml_user_suffix': '@test.eduid.se',
                'token_service_url': 'http://login',
            }
        )
        return config

    def load_app(self, test_config: Mapping[str, Any]) -> AuthnTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        config = load_config(typ=AuthnConfig, app_name='testing', ns='webapp', test_config=test_config)
        return AuthnTestApp(config)

    def test_no_cookie(self):
        with self.app.test_client() as c:
            resp = c.get('/')
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.location.startswith(self.app.conf.token_service_url))

    def test_cookie(self):
        sessid = 'fb1f42420b0109020203325d750185673df252de388932a3957f522a6c43a' 'a47'
        self.redis_instance.conn.set(sessid, json.dumps({'v1': {'id': '0'}}))

        with self.session_cookie(self.browser, self.test_user.eppn) as c:
            self.assertRaises(NotFound, c.get, '/')


class NoAuthnAPITestCase(EduidAPITestCase):
    """ Tests for a fictitious app based on AuthnBaseApp """

    app: AuthnTestApp

    def setUp(self):
        super(NoAuthnAPITestCase, self).setUp()
        test_views = Blueprint('testing', __name__)

        @test_views.route('/test')
        def test():
            return 'OK'

        @test_views.route('/test2')
        def test2():
            return 'OK'

        @test_views.route('/test3')
        def test3():
            return 'OK'

        self.app.register_blueprint(test_views)

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        saml_config = os.path.join(HERE, 'saml2_settings.py')
        config.update(
            {
                'no_authn_urls': ['^/test$'],
                'saml2_login_redirect_url': '/',
                'saml2_logout_redirect_url': '/',
                'saml2_settings_module': saml_config,
                'saml2_strip_saml_user_suffix': '@test.eduid.se',
                'token_service_url': 'http://login',
            }
        )
        return config

    def load_app(self, test_config: Mapping[str, Any]) -> AuthnTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        config = load_config(typ=AuthnConfig, app_name='testing', ns='webapp', test_config=test_config)
        return AuthnTestApp(config)

    def test_no_authn(self):
        with self.app.test_client() as c:
            resp = c.get('/test')
            self.assertEqual(resp.status_code, 200)

    def test_authn(self):
        with self.app.test_client() as c:
            resp = c.get('/test2')
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.location.startswith(self.app.conf.token_service_url))

    def test_no_authn_util(self):
        no_authn_urls_before = [path for path in self.app.conf.no_authn_urls]
        no_authn_path = '/test3'
        no_authn_views(self.app.conf, [no_authn_path])
        self.assertEqual(no_authn_urls_before + ['^{!s}$'.format(no_authn_path)], self.app.conf.no_authn_urls)

        with self.app.test_client() as c:
            resp = c.get('/test3')
            self.assertEqual(resp.status_code, 200)


class LogoutRequestTests(AuthnAPITestBase):
    def test_metadataview(self):
        with self.app.test_client() as c:
            response = c.get('/saml2-metadata')
            self.assertEqual(response.status, '200 OK')

    def test_logout_nologgedin(self):
        eppn = 'hubba-bubba'
        with self.app.test_request_context('/logout', method='GET'):
            # eppn is set in the IdP
            session.common.eppn = eppn
            response = self.app.dispatch_request()
            self.assertEqual(response.status, '302 FOUND')
            self.assertIn(self.app.conf.saml2_logout_redirect_url, response.headers['Location'])

    def test_logout_loggedin(self):
        eppn = 'hubba-bubba'
        came_from = '/afterlogin/'
        cookie = self.login(eppn, came_from)

        with self.app.test_request_context('/logout', method='GET', headers={'Cookie': cookie}):
            response = self.app.dispatch_request()
            self.assertEqual(response.status, '302 FOUND')
            self.assertIn(
                'https://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php', response.headers['location']
            )

    def test_logout_service_startingSP(self):

        came_from = '/afterlogin/'
        session_id = self.add_outstanding_query(came_from)
        cookie = self.dump_session_cookie(session_id)

        with self.app.test_request_context(
            '/saml2-ls',
            method='POST',
            headers={'Cookie': cookie},
            data={
                'SAMLResponse': deflate_and_base64_encode(logout_response(session_id)),
                'RelayState': '/testing-relay-state',
            },
        ):
            response = self.app.dispatch_request()

            self.assertEqual(response.status, '302 FOUND')
            self.assertIn('testing-relay-state', response.location)

    def test_logout_service_startingSP_already_logout(self):

        came_from = '/afterlogin/'
        session_id = self.add_outstanding_query(came_from)

        with self.app.test_request_context(
            '/saml2-ls',
            method='POST',
            data={
                'SAMLResponse': deflate_and_base64_encode(logout_response(session_id)),
                'RelayState': '/testing-relay-state',
            },
        ):
            response = self.app.dispatch_request()

            self.assertEqual(response.status, '302 FOUND')
            self.assertIn('testing-relay-state', response.location)

    def test_logout_service_startingIDP(self):

        eppn = 'hubba-bubba'
        came_from = '/afterlogin/'
        session_id = self.add_outstanding_query(came_from)
        cookie = self.dump_session_cookie(session_id)

        saml_response = auth_response(session_id, eppn).encode('utf-8')

        # Log in through IDP SAMLResponse
        with self.app.test_request_context(
            '/saml2-acs',
            method='POST',
            headers={'Cookie': cookie},
            data={'SAMLResponse': base64.b64encode(saml_response), 'RelayState': '/testing-relay-state',},
        ):
            self.app.dispatch_request()
            session.persist()  # Explicit session.persist is needed when working within a test_request_context

        with self.app.test_request_context(
            '/saml2-ls',
            method='POST',
            headers={'Cookie': cookie},
            data={
                'SAMLRequest': deflate_and_base64_encode(logout_request(session_id)),
                'RelayState': '/testing-relay-state',
            },
        ):
            response = self.app.dispatch_request()

            self.assertEqual(response.status, '302 FOUND')
            assert (
                'https://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php?SAMLResponse='
                in response.location
            )

    def test_logout_service_startingIDP_no_subject_id(self):

        eppn = 'hubba-bubba'
        came_from = '/afterlogin/'
        session_id = self.add_outstanding_query(came_from)
        cookie = self.dump_session_cookie(session_id)

        saml_response = auth_response(session_id, eppn).encode('utf-8')

        # Log in through IDP SAMLResponse
        with self.app.test_request_context(
            '/saml2-acs',
            method='POST',
            headers={'Cookie': cookie},
            data={'SAMLResponse': base64.b64encode(saml_response), 'RelayState': '/testing-relay-state',},
        ):
            self.app.dispatch_request()
            session.persist()  # Explicit session.persist is needed when working within a test_request_context

        with self.app.test_request_context(
            '/saml2-ls',
            method='POST',
            headers={'Cookie': cookie},
            data={
                'SAMLRequest': deflate_and_base64_encode(logout_request(session_id)),
                'RelayState': '/testing-relay-state',
            },
        ):
            session.authn.name_id = None
            session.persist()  # Explicit session.persist is needed when working within a test_request_context
            response = self.app.dispatch_request()

            self.assertEqual(response.status, '302 FOUND')
            self.assertIn('testing-relay-state', response.location)
