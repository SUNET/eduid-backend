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

import six
import os
import time
from datetime import datetime
import json
import base64
from hashlib import sha256

from nacl import secret, utils, encoding
from werkzeug.exceptions import NotFound
from werkzeug.http import dump_cookie
from flask import Blueprint
from saml2.s_utils import deflate_and_base64_encode

from eduid_common.session import session
from eduid_common.api.testing import EduidAPITestCase
from eduid_common.authn.cache import OutstandingQueriesCache
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_common.authn.utils import get_location, no_authn_views
from eduid_common.authn.eduid_saml2 import get_authn_request
from eduid_common.authn.tests.responses import (auth_response,
                                                logout_response,
                                                logout_request)
from eduid_webapp.authn.settings.common import AuthnConfig
from eduid_webapp.authn.app import authn_init_app
from eduid_webapp.authn.app import AuthnApp

from six.moves.urllib_parse import quote_plus

import logging
logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


class AuthnAPITestBase(EduidAPITestCase):

    def update_config(self, app_config):
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        saml_config = os.path.join(HERE, 'saml2_settings.py')
        app_config.update({
            'saml2_login_redirect_url': '/',
            'saml2_logout_redirect_url': '/logged-out',
            'saml2_settings_module': saml_config,
            'signup_authn_success_redirect_url': 'http://test.localhost/success',
            'signup_authn_failure_redirect_url': 'http://test.localhost/failure',
            'safe_relay_domain': 'test.localhost'
            })
        return AuthnConfig(**app_config)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return authn_init_app('testing', config)

    def add_outstanding_query(self, came_from):
        """
        Add a SAML2 authentication query to the queries cache.
        To be used before accessing the assertion consumer service.

        :param came_from: url to redirect back the client
                          after finishing with the authn service.
        :type came_from: str

        :return: the session token corresponding to the query
        :rtype: str
        """
        with self.app.test_request_context('/login'):
            self.app.dispatch_request()
            oq_cache = OutstandingQueriesCache(session)
            token = session.token
            if isinstance(token, six.binary_type):
                token = token.decode('ascii')
            oq_cache.set(token, came_from)
            session.persist()  # Explicit session.persist is needed when working within a test_request_context
            return token

    def login(self, eppn, came_from):
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
        :type eppn: str
        :param came_from: url to redirect back the client
                          after finishing with the authn service.
        :type came_from: str

        :return: the cookie corresponding to the authn session
        :rtype: str
        """
        session_id = self.add_outstanding_query(came_from)
        cookie = self.dump_session_cookie(session_id)
        saml_response = auth_response(session_id, eppn).encode('utf-8')

        with self.app.test_request_context('/saml2-acs', method='POST',
                                           headers={'Cookie': cookie},
                                           data={'SAMLResponse': base64.b64encode(saml_response),
                                                 'RelayState': came_from}):

            self.app.dispatch_request()
            session.persist()  # Explicit session.persist is needed when working within a test_request_context
            return cookie

    def authn(self, url, force_authn=False, next_url='/'):
        """
        Common code for the tests that need to send an authentication request.
        This checks that the client is redirected to the idp.

        :param url: the url of the desired authentication mode.
        :type url: str
        :param force_authn: whether to force reauthentication for an already
                            authenticated client
        :type force_authn: bool
        :param next_url: Next url
        :type next_url: six.string_types
        """
        with self.app.test_client() as c:
            resp = c.get('{}?next={}'.format(url, next_url))
            authn_req = get_location(get_authn_request(self.app.saml2_config,
                                                       session, next_url, None,
                                                       force_authn=force_authn))
            idp_url = authn_req.split('?')[0]
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.location.startswith(idp_url))
            relay_state = resp.location.split('&')[-1]
            quoted_next = 'RelayState={}'.format(quote_plus(next_url))
            self.assertEqual(quoted_next, relay_state)

    def acs(self, url, eppn, check_fn, came_from='/camefrom/'):
        """
        common code for the tests that need to access the assertion consumer service
        and then check the side effects of this access.

        :param url: the url of the desired authentication mode.
        :type url: str
        :param eppn: the eppn of the user to access the service
        :type eppn: str
        :param check_fn: the function that checks the side effects after accessing the acs
        :type check_fn: callable
        :param came_from: Relay state
        :type came_from: six.string_types
        """
        with self.app.test_client() as c:
            resp = c.get(url)
            cookie = resp.headers['Set-Cookie']
            token = session._session.token
            if isinstance(token, six.binary_type):
                token = token.decode('ascii')
            authr = auth_response(token, eppn).encode('utf-8')

        with self.app.test_request_context('/saml2-acs', method='POST',
                                           headers={'Cookie': cookie},
                                           data={'SAMLResponse': base64.b64encode(authr),
                                                 'RelayState': came_from}):

            oq_cache = OutstandingQueriesCache(session)
            oq_cache.set(token, came_from)

            resp = self.app.dispatch_request()

            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.location, came_from)
            check_fn()

    def dump_session_cookie(self, session_id):
        """
        Get a cookie corresponding to an authenticated session.

        :param session_id: the token for the session
        :type session_id: str

        :return: the cookie
        """
        return dump_cookie(self.app.config.session_cookie_name, session_id,
                           max_age=float(self.app.config.permanent_session_lifetime),
                           path=self.app.config.session_cookie_path,
                           domain=self.app.config.session_cookie_domain)


class AuthnAPITestCase(AuthnAPITestBase):
    """
    Tests to check the different modes of authentication.
    """

    def setUp(self):
        super(AuthnAPITestCase, self).setUp(users=['hubba-bubba', 'hubba-fooo'])

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
            eppn = 'hubba-bubba'
            self.assertEqual(session['eduPersonPrincipalName'], eppn)

        self.acs('/login', eppn, _check)

    def test_login_assertion_consumer_service_good_relay_state(self):
        eppn = 'hubba-bubba'

        def _check():
            eppn = 'hubba-bubba'
            self.assertEqual(session['eduPersonPrincipalName'], eppn)

        self.acs('/login', eppn, _check, came_from='http://test.localhost/profile/')

    def test_login_assertion_consumer_service_bad_relay_state(self):
        eppn = 'hubba-bubba'

        def _check():
            eppn = 'hubba-bubba'
            self.assertEqual(session['eduPersonPrincipalName'], eppn)

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

    def test_signup_authn_new_user(self):
        eppn = 'hubba-fooo'
        timestamp = datetime.fromtimestamp(time.time())

        with self.app.test_client() as c:
            with self.app.test_request_context('/signup-authn'):
                c.set_cookie('test.localhost',
                             key=self.app.config.session_cookie_name,
                             value=session._session.token)
                session.common.eppn = eppn
                session.signup.ts = timestamp

                resp = self.app.dispatch_request()
                self.assertEqual(resp.status_code, 302)
                self.assertTrue(resp.location.startswith(self.app.config.signup_authn_success_redirect_url))

    def test_signup_authn_old_user(self):
        """ A user that has verified their account should not try to use token login """
        eppn = 'hubba-bubba'
        timestamp = datetime.fromtimestamp(time.time())

        with self.app.test_client() as c:
            with self.app.test_request_context('/signup-authn'):
                c.set_cookie('test.localhost',
                             key=self.app.config.session_cookie_name,
                             value=session._session.token)
                session.common.eppn = eppn
                session.signup.ts = timestamp

                resp = self.app.dispatch_request()
                self.assertEqual(resp.status_code, 302)
                self.assertTrue(resp.location.startswith(self.app.config.signup_authn_failure_redirect_url))


class UnAuthnAPITestCase(EduidAPITestCase):

    def update_config(self, app_config):
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        saml_config = os.path.join(HERE, 'saml2_settings.py')
        app_config.update({
            'token_service_url': 'http://login',
            'saml2_settings_module': saml_config,
            })
        return AuthnConfig(**app_config)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return AuthnBaseApp('testing', AuthnConfig, config)

    def test_no_cookie(self):
        with self.app.test_client() as c:
            resp = c.get('/')
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.location.startswith(self.app.config.token_service_url))

    def test_cookie(self):
        token = ('a7MPUEQQLAEEQEAQDGJOXKAMFM467EUW6HCETFI4VP5JCU3CDVJDQZSHMXAOSC'
                 'U25WPZA66NY5ZVAA4RPCVMHBQBJSVGYQPPLZNIBTP3Y')
        sessid = ('fb1f42420b0109020203325d750185673df252de388932a3957f522a6c43a'
                  'a47')
        self.redis_instance.conn.set(sessid, json.dumps({'v1': {'id': '0'}}))

        with self.session_cookie(self.browser, self.test_user.eppn) as c:
            self.assertRaises(NotFound, c.get, '/')


class NoAuthnAPITestCase(EduidAPITestCase):

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

    def update_config(self, app_config):
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        saml_config = os.path.join(HERE, 'saml2_settings.py')
        app_config.update({
            'token_service_url': 'http://login',
            'saml2_settings_module': saml_config,
            'no_authn_urls': ['^/test$'],
            })
        return AuthnConfig(**app_config)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return AuthnBaseApp('testing', AuthnConfig, config)

    def test_no_authn(self):
        with self.app.test_client() as c:
            resp = c.get('/test')
            self.assertEqual(resp.status_code, 200)

    def test_authn(self):
        with self.app.test_client() as c:
            resp = c.get('/test2')
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.location.startswith(self.app.config.token_service_url))

    def test_no_authn_util(self):
        no_authn_urls_before = [path for path in self.app.config.no_authn_urls]
        no_authn_path = '/test3'
        no_authn_views(self.app, [no_authn_path])
        self.assertEqual(no_authn_urls_before + ['^{!s}$'.format(no_authn_path)], self.app.config.no_authn_urls)

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
        csrft = 'csrf token'
        with self.app.test_request_context('/logout', method='GET'):
            # user_eppn is set in the IdP
            session['user_eppn'] = eppn
            response = self.app.dispatch_request()
            self.assertEqual(response.status, '302 FOUND')
            self.assertIn(self.app.config.saml2_logout_redirect_url,
                          response.headers['Location'])

    def test_logout_loggedin(self):
        eppn = 'hubba-bubba'
        came_from = '/afterlogin/'
        cookie = self.login(eppn, came_from)

        with self.app.test_request_context('/logout', method='GET', headers={'Cookie': cookie}):
            response = self.app.dispatch_request()
            self.assertEqual(response.status, '302 FOUND')
            self.assertIn('https://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php',
                          response.headers['location'])

    def test_logout_service_startingSP(self):

        came_from = '/afterlogin/'
        session_id = self.add_outstanding_query(came_from)
        cookie = self.dump_session_cookie(session_id)

        with self.app.test_request_context('/saml2-ls', method='POST',
                                           headers={'Cookie': cookie},
                                           data={'SAMLResponse': deflate_and_base64_encode(
                                            logout_response(session_id)
                                           ),
                                               'RelayState': '/testing-relay-state',
                                           }):
            response = self.app.dispatch_request()

            self.assertEqual(response.status, '302 FOUND')
            self.assertIn('testing-relay-state', response.location)

    def test_logout_service_startingSP_already_logout(self):

        came_from = '/afterlogin/'
        session_id = self.add_outstanding_query(came_from)

        with self.app.test_request_context('/saml2-ls', method='POST',
                                           data={'SAMLResponse': deflate_and_base64_encode(
                                               logout_response(session_id)
                                           ),
                                               'RelayState': '/testing-relay-state',
                                           }):
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
        with self.app.test_request_context('/saml2-acs', method='POST',
                                           headers={'Cookie': cookie},
                                           data={'SAMLResponse': base64.b64encode(saml_response),
                                                 'RelayState': '/testing-relay-state',
                                                 }):
            self.app.dispatch_request()
            session.persist()  # Explicit session.persist is needed when working within a test_request_context

        with self.app.test_request_context('/saml2-ls', method='POST',
                                           headers={'Cookie': cookie},
                                           data={'SAMLRequest': deflate_and_base64_encode(
                                               logout_request(session_id)
                                           ),
                                               'RelayState': '/testing-relay-state',
                                           }):
            response = self.app.dispatch_request()

            self.assertEqual(response.status, '302 FOUND')
            self.assertIn('https://idp.example.com/simplesaml/saml2/idp/'
                          'SingleLogoutService.php?SAMLResponse=', response.location)

    def test_logout_service_startingIDP_no_subject_id(self):

        eppn = 'hubba-bubba'
        came_from = '/afterlogin/'
        session_id = self.add_outstanding_query(came_from)
        cookie = self.dump_session_cookie(session_id)

        saml_response = auth_response(session_id, eppn).encode('utf-8')

        # Log in through IDP SAMLResponse
        with self.app.test_request_context('/saml2-acs', method='POST',
                                           headers={'Cookie': cookie},
                                           data={'SAMLResponse': base64.b64encode(saml_response),
                                                 'RelayState': '/testing-relay-state',
                                                 }):
            self.app.dispatch_request()
            session.persist()  # Explicit session.persist is needed when working within a test_request_context

        with self.app.test_request_context('/saml2-ls', method='POST',
                                           headers={'Cookie': cookie},
                                           data={'SAMLRequest': deflate_and_base64_encode(
                                               logout_request(session_id)
                                           ),
                                               'RelayState': '/testing-relay-state',
                                           }):
            del session['_saml2_session_name_id']
            session.persist()  # Explicit session.persist is needed when working within a test_request_context
            response = self.app.dispatch_request()

            self.assertEqual(response.status, '302 FOUND')
            self.assertIn('testing-relay-state', response.location)
