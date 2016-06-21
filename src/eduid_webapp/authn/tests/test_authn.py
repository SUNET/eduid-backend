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

import os
import json
import time
import base64

from werkzeug.exceptions import NotFound
from werkzeug.http import dump_cookie
from flask import session
from webtest import TestApp, TestRequest

from eduid_common.api.testing import EduidAPITestCase
from eduid_common.api.app import eduid_init_app
from eduid_common.authn.cache import OutstandingQueriesCache
from eduid_common.authn.utils import get_location
from eduid_common.authn.eduid_saml2 import get_authn_request
from eduid_common.authn.tests.responses import auth_response
from eduid_common.session.session import SessionManager
from eduid_webapp.authn.app import authn_init_app

import logging
logger = logging.getLogger(__name__)


HERE = os.path.abspath(os.path.dirname(__file__))


class AuthnAPITestBase(EduidAPITestCase):

    def update_config(self, config):
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        saml_config = os.path.join(HERE, 'saml2_settings.py')
        config.update({
            'SAML2_LOGIN_REDIRECT_URL': '/',
            'SAML2_LOGOUT_REDIRECT_URL': '/logged-out',
            'SAML2_SETTINGS_MODULE': saml_config,
            })
        return config

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return authn_init_app('test.localhost', config)

    def _authn(self, url, force_authn=False):
        with self.app.test_client() as c:
            resp = c.get(url)
            authn_req = get_location(get_authn_request(self.app.config,
                                                       session, '/', None,
                                                       force_authn=force_authn))
            idp_url = authn_req.split('?')[0]
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.location.startswith(idp_url))

    def _acs(self, url, check_fn):
        came_from = '/camefrom/'
        eppn = 'hubba-bubba'
        with self.app.test_client() as c:
            resp = c.get(url)
            cookie = resp.headers['Set-Cookie']
            token = session._session.token
            authr = auth_response(token, eppn)

        with self.app.test_request_context('/saml2-acs', method='POST',
                                           headers={'Cookie': cookie},
                                           data={'SAMLResponse': base64.b64encode(authr),
                                                 'RelayState': came_from}):

            oq_cache = OutstandingQueriesCache(session)
            oq_cache.set(token, came_from)

            resp = self.app.dispatch_request()

            self.assertEquals(resp.status_code, 302)
            self.assertEquals(resp.location, came_from)
            check_fn()


class LoginAPITestCase(AuthnAPITestBase):

    def test_authn(self):
        self._authn('/login')

    def test_assertion_consumer_service(self):
        def _check():
            eppn = 'hubba-bubba'
            self.assertEquals(session['eduPersonPrincipalName'], eppn)

        self._acs('/login', _check)


class ChpassAPITestCase(AuthnAPITestBase):

    def test_authn(self):
        self._authn('/chpass', force_authn=True)

    def test_assertion_consumer_service(self):
        def _check():
            self.assertIn('reauthn-for-chpass', session)
            then = session['reauthn-for-chpass']
            now = int(time.time())
            self.assertTrue(now - then < 5)

        self._acs('/chpass', _check)


class TerminationAPITestCase(AuthnAPITestBase):

    def test_authn(self):
        self._authn('/terminate', force_authn=True)

    def test_assertion_consumer_service(self):
        def _check():
            self.assertIn('reauthn-for-termination', session)
            then = session['reauthn-for-termination']
            now = int(time.time())
            self.assertTrue(now - then < 5)

        self._acs('/terminate', _check)


class UnAuthnAPITestCase(EduidAPITestCase):

    def update_config(self, config):
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        saml_config = os.path.join(HERE, 'saml2_settings.py')
        config.update({
            'TOKEN_SERVICE_URL': 'http://login',
            'SAML2_SETTINGS_MODULE': saml_config,
            })
        return config

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return eduid_init_app('testing', config)

    def test_no_cookie(self):
        with self.app.test_client() as c:
            resp = c.get('/')
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.location.startswith(self.app.config['TOKEN_SERVICE_URL']))

    def test_cookie(self):
        token = ('a7MPUEQQLAEEQEAQDGJOXKAMFM467EUW6HCETFI4VP5JCU3CDVJDQZSHMXAOSC'
                 'U25WPZA66NY5ZVAA4RPCVMHBQBJSVGYQPPLZNIBTP3Y')
        sessid = ('fb1f42420b0109020203325d750185673df252de388932a3957f522a6c43a'
                  'a47')
        self.redis_instance.conn.set(sessid, json.dumps({'v1': {'id': '0'}}))

        with self.app.test_client() as c:
            cookie_name = self.app.config.get('SESSION_COOKIE_NAME')
            c.set_cookie('localhost', cookie_name, token)
            self.assertRaises(NotFound, c.get, '/')


class Saml2RequestTests(AuthnAPITestBase):

    def _loggedin(self, check_fn):
        token = ('a7MPUEQQLAEEQEAQDGJOXKAMFM467EUW6HCETFI4VP5JCU3CDVJDQZSHMXAOSC'
                 'U25WPZA66NY5ZVAA4RPCVMHBQBJSVGYQPPLZNIBTP3Y')
        sessid = ('fb1f42420b0109020203325d750185673df252de388932a3957f522a6c43a'
                  'a47')
        self.redis_instance.conn.set(sessid, json.dumps({'v1': {'id': '0'}}))

        with self.app.test_client() as c:
            cookie_name = self.app.config.get('SESSION_COOKIE_NAME')
            c.set_cookie('localhost', cookie_name, token)
            check_fn(c)

    def add_outstanding_query(self, came_from):
        with self.app.test_request_context('/login'):
            response1 = self.app.dispatch_request()
            oq_cache = OutstandingQueriesCache(session)
            oq_cache.set(session.token, came_from)
            session.persist()
            return session.token

    def test_metadataview(self):
        with self.app.test_client() as c:
            response = c.get('/saml2-metadata')
            self.assertEqual(response.status, '200 OK')

    def test_logout_nologgedin(self):
        csrft = 'csrf token'
        with self.app.test_request_context('/logout', method='POST',
                                    data={'csrf': csrft}):
            session['_csrft_'] = csrft
            session['user_eppn'] = 'hubba-bubba'
            session['eduPersonPrincipalName'] = 'hubba-bubba'
            response = self.app.dispatch_request()
            self.assertEqual(response.status, '302 FOUND')
            self.assertIn(self.app.config['SAML2_LOGOUT_REDIRECT_URL'], response.location)

    def test_logout_loggedin(self):
        came_from = '/afterlogin/'
        session_id = self.add_outstanding_query(came_from)
        cookie_name = self.app.config.get('SESSION_COOKIE_NAME')
        cookie = dump_cookie(cookie_name, session_id,
                             max_age=float(self.app.config.get('PERMANENT_SESSION_LIFETIME')),
                             path=self.app.config.get('SESSION_COOKIE_PATH'),
                             domain=self.app.config.get('SESSION_COOKIE_DOMAIN'))

        saml_response = auth_response(session_id, "hubba-bubba")

        with self.app.test_request_context('/saml2-acs', method='POST',
                                headers={'Cookie': cookie},
                                    data={'SAMLResponse': base64.b64encode(saml_response),
                                                 'RelayState': came_from}):
 
            response1 = self.app.dispatch_request()
            cookie = response1.headers['Set-Cookie']
 
        csrft = 'csrf token'
        with self.app.test_request_context('/logout', method='POST',
                                headers={'Cookie': cookie},
                                data={'csrf': csrft}):
            session['_csrft_'] = csrft
            response2 = self.app.dispatch_request()
            self.assertEqual(response2.status, '302 FOUND')
            self.assertIn('https://idp.example.com/simplesaml/saml2/idp/'
                           'SingleLogoutService.php', response2.location)
 
#     def test_logout_service_startingSP(self):
#         self.config.testing_securitypolicy(userid='user1@example.com',
#                                            permissive=True)
#         self.set_user_cookie('user1@example.com')
# 
#         came_from = '/afterlogin/'
#         session_id = self.add_outstanding_query(came_from)
# 
#         res = self.testapp.get('/saml2/ls/', params={
#             'SAMLResponse': deflate_and_base64_encode(
#                 logout_response(session_id)
#             ),
#             'RelayState': 'testing-relay-state',
#         })
# 
#         self.assertEqual(res.status, '302 Found')
#         self.assertIn(self.settings['saml2.logout_redirect_url'], res.location)
#         # Set a expired cookie (just the logout header)
#         self.assertIn('auth_tkt=""; Path=/; Domain=localhost; Max-Age=0; '
#                       'Expires=Wed, 31-Dec-97 23:59:59 GMT',
#                       res.headers.getall('Set-Cookie'))
# 
#     def test_logout_service_startingSP_already_logout(self):
# 
#         came_from = '/afterlogin/'
#         session_id = self.add_outstanding_query(came_from)
# 
#         res = self.testapp.get('/saml2/ls/', params={
#             'SAMLResponse': deflate_and_base64_encode(
#                 logout_response(session_id)
#             ),
#             'RelayState': 'testing-relay-state',
#         })
# 
#         self.assertEqual(res.status, '302 Found')
#         self.assertIn(self.settings['saml2.logout_redirect_url'], res.location)
#         # Set a expired cookie (just the logout header)
#         self.assertIn('auth_tkt=""; Path=/; Domain=localhost; Max-Age=0; '
#                       'Expires=Wed, 31-Dec-97 23:59:59 GMT',
#                       res.headers.getall('Set-Cookie'))
# 
#     def test_logout_service_startingIDP(self):
#         self.config.testing_securitypolicy(userid='user1@example.com',
#                                            permissive=True)
#         self.set_user_cookie('user1@example.com')
# 
#         came_from = '/afterlogin/'
# 
#         session_id = self.add_outstanding_query(came_from)
# 
#         saml_response = auth_response(session_id, "hubba-bubba@test")
# 
#         # Log in through IDP SAMLResponse
#         res = self.testapp.post('/saml2/acs/', params={
#             'SAMLResponse': base64.b64encode(saml_response),
#             'RelayState': came_from,
#         })
# 
#         res = self.testapp.get('/saml2/ls/', params={
#             'SAMLRequest': deflate_and_base64_encode(
#                 logout_request(session_id)
#             ),
#             'RelayState': 'testing-relay-state',
#         })
# 
#         self.assertEqual(res.status, '302 Found')
#         self.assertIn('https://idp.example.com/simplesaml/saml2/idp/'
#                       'SingleLogoutService.php?SAMLResponse=', res.location)
#         # Set a expired cookie (just the logout header)
#         self.assertIn('auth_tkt=""; Path=/; Domain=localhost; Max-Age=0; '
#                       'Expires=Wed, 31-Dec-97 23:59:59 GMT',
#                       res.headers.getall('Set-Cookie'))
