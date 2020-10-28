# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
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

from __future__ import absolute_import

import os
import re
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple

import pkg_resources
from flask import Response as FlaskResponse
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.response import AuthnResponse

from eduid_common.api.testing import EduidAPITestCase
from eduid_common.authn.cache import IdentityCache, OutstandingQueriesCache, StateCache
from eduid_common.authn.utils import get_saml2_config

from eduid_webapp.idp.app import init_idp_app

__author__ = 'ft'


class LoginState(Enum):
    S0_REDIRECT = 'redirect'
    S1_LOGIN_FORM = 'login-form'
    S2_VERIFY = 'verify'
    S3_REDIRECT_LOGGED_IN = 'redirect-logged-in'
    S4_REDIRECT_TO_ACS = 'redirect-to-acs'
    S5_LOGGED_IN = 'logged-in'


class IdPTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        super().setUp()
        self.idp_entity_id = 'https://unittest-idp.example.edu/idp.xml'
        self.relay_state = 'test-fest'
        self.sp_config = get_saml2_config(self.app.config.pysaml2_config, name='SP_CONFIG')
        # pysaml2 likes to keep state about ongoing logins, data from login to when you logout etc.
        self._pysaml2_caches = dict()
        self.pysaml2_state = StateCache(self._pysaml2_caches)  # _saml2_state in _pysaml2_caches
        self.pysaml2_identity = IdentityCache(self._pysaml2_caches)  # _saml2_identities in _pysaml2_caches
        self.pysaml2_oq = OutstandingQueriesCache(self._pysaml2_caches)  # _saml2_outstanding_queries in _pysaml2_caches
        self.saml2_client = Saml2Client(config=self.sp_config, identity_cache=self.pysaml2_identity)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_idp_app('testing', config)

    def update_config(self, config):
        config = super().update_config(config)
        datadir = pkg_resources.resource_filename(__name__, 'data')
        fn = os.path.join(datadir, 'test_SSO_conf.py')
        config.update({'pysaml2_config': fn, 'fticks_secret_key': 'test test'})
        return config

    def tearDown(self):
        super(IdPTests, self).tearDown()
        with self.app.app_context():
            self.app.central_userdb._drop_whole_collection()

    def test_app_starts(self):
        assert self.app.config.app_name =='idp'


    def _try_login(
        self, saml2_client: Optional[Saml2Client] = None, authn_context=None, force_authn: bool=False,
    ) -> Tuple[LoginState, FlaskResponse]:
        """
        Try logging in to the IdP.

        :return: Information about how far we got (reached LoginState) and the last response instance.
        """
        _saml2_client = saml2_client if saml2_client is not None else self.saml2_client

        (session_id, info) = _saml2_client.prepare_for_authenticate(
            entityid=self.idp_entity_id,
            relay_state=self.relay_state,
            binding=BINDING_HTTP_REDIRECT,
            requested_authn_context=authn_context,
            force_authn=force_authn,
        )
        self.pysaml2_oq.set(session_id, self.relay_state)

        path = self._extract_path_from_info(info)
        with self.session_cookie_anon(self.browser) as browser:
            resp = browser.get(path)
            if resp.status_code != 200:
                return LoginState.S0_REDIRECT, resp

        form_data = self._extract_form_inputs(resp.data.decode('utf-8'))
        del form_data['key']  # test if key is really necessary
        form_data['username'] = self.test_user.mail_addresses.primary.email
        form_data['password'] = 'Jenka'
        if 'redirect_uri' not in form_data:
            return LoginState.S1_LOGIN_FORM, resp

        cookies = resp.headers.get('Set-Cookie')
        if not cookies:
            return LoginState.S1_LOGIN_FORM, resp

        with self.session_cookie_anon(self.browser) as browser:
            resp = browser.post('/verify', data=form_data, headers={'Cookie': cookies})
            if resp.status_code != 302:
                return LoginState.S2_VERIFY, resp

        redirect_loc = self._extract_path_from_response(resp)
        # check that we were sent back to the login screen
        # TODO: verify that we really were logged in
        if not redirect_loc.startswith('/sso/redirect?key='):
            return LoginState.S2_VERIFY, resp

        cookies = resp.headers.get('Set-Cookie')
        if not cookies:
            return LoginState.S2_VERIFY, resp

        resp = self.browser.get(redirect_loc, headers={'Cookie': cookies})
        if resp.status_code != 200:
            return LoginState.S3_REDIRECT_LOGGED_IN, resp

        return LoginState.S5_LOGGED_IN, resp

    def _extract_form_inputs(self, res: str) -> Dict[str, Any]:
        inputs = {}
        for line in res.split('\n'):
            if 'input' in line:
                # YOLO
                m = re.match('.*<input .* name=[\'"](.+?)[\'"].*value=[\'"](.+?)[\'"]', line)
                if m:
                    name, value = m.groups()
                    inputs[name] = value.strip('\'"')
        return inputs

    def _extract_path_from_response(self, response: FlaskResponse) -> str:
        return self._extract_path_from_info({'headers': response.headers})

    def _extract_path_from_info(self, info: Mapping[str, Any]) -> str:
        _location_headers = [_hdr for _hdr in info['headers'] if _hdr[0] == 'Location']
        # get first Location URL
        loc = _location_headers[0][1]
        return self._extract_path_from_url(loc)

    def _extract_path_from_url(self, url):
        # It is a complete URL, extract the path from it (8 is to skip over slashes in https://)
        _idx = url[8:].index('/')
        path = url[8 + _idx :]
        return path

    def parse_saml_authn_response(self, response: FlaskResponse) -> AuthnResponse:
        form = self._extract_form_inputs(response.data.decode('utf-8'))
        xmlstr = bytes(form['SAMLResponse'], 'ascii')
        outstanding_queries = self.pysaml2_oq.outstanding_queries()
        return self.saml2_client.parse_authn_request_response(xmlstr, BINDING_HTTP_POST, outstanding_queries)
