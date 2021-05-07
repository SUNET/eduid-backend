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
import re
from base64 import b64decode
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePath
from typing import Any, Dict, List, Mapping, Optional

from flask import Response as FlaskResponse
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.response import AuthnResponse

from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.cache import IdentityCache, OutstandingQueriesCache, StateCache
from eduid.webapp.common.authn.utils import get_saml2_config
from eduid.webapp.idp.app import IdPApp, init_idp_app
from eduid.webapp.idp.sso_session import SSOSession

__author__ = 'ft'


class LoginState(Enum):
    S0_REDIRECT = 'redirect'
    S1_LOGIN_FORM = 'login-form'
    S2_VERIFY = 'verify'
    S3_REDIRECT_LOGGED_IN = 'redirect-logged-in'
    S4_REDIRECT_TO_ACS = 'redirect-to-acs'
    S5_LOGGED_IN = 'logged-in'


@dataclass
class LoginResult:
    url: str
    reached_state: LoginState
    response: FlaskResponse
    sso_cookie_val: Optional[str] = None


class IdPTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(
        self, *args, **kwargs,
    ):
        super().setUp(*args, **kwargs)
        self.idp_entity_id = 'https://unittest-idp.example.edu/idp.xml'
        self.relay_state = 'test-fest'
        self.sp_config = get_saml2_config(self.app.conf.pysaml2_config, name='SP_CONFIG')
        # pysaml2 likes to keep state about ongoing logins, data from login to when you logout etc.
        self._pysaml2_caches: Dict[str, Any] = dict()
        self.pysaml2_state = StateCache(self._pysaml2_caches)  # _saml2_state in _pysaml2_caches
        self.pysaml2_identity = IdentityCache(self._pysaml2_caches)  # _saml2_identities in _pysaml2_caches
        self.pysaml2_oq = OutstandingQueriesCache(self._pysaml2_caches)  # _saml2_outstanding_queries in _pysaml2_caches
        self.saml2_client = Saml2Client(config=self.sp_config, identity_cache=self.pysaml2_identity)

    def load_app(self, config: Optional[Mapping[str, Any]]) -> IdPApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_idp_app(test_config=config)

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        config = super().update_config(config)
        fn = PurePath(__file__).with_name('data') / 'test_SSO_conf.py'
        config.update(
            {
                'pysaml2_config': str(fn),
                'fticks_secret_key': 'test test',
                'eduperson_targeted_id_secret_key': 'eptid_secret',
                'sso_cookie': {'key': 'test_sso_cookie'},
                'eduid_site_url': 'https://eduid.docker_dev',
            }
        )
        return config

    def tearDown(self):
        super(IdPTests, self).tearDown()
        with self.app.app_context():
            self.app.central_userdb._drop_whole_collection()

    def test_app_starts(self):
        assert self.app.conf.app_name == 'idp'

    def _try_login(
        self,
        saml2_client: Optional[Saml2Client] = None,
        authn_context=None,
        force_authn: bool = False,
        assertion_consumer_service_url: Optional[str] = None,
    ) -> LoginResult:
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
            assertion_consumer_service_url=assertion_consumer_service_url,
        )
        self.pysaml2_oq.set(session_id, self.relay_state)

        path = self._extract_path_from_info(info)
        with self.session_cookie_anon(self.browser) as browser:
            resp = browser.get(path)
            if resp.status_code != 200:
                return LoginResult(url=path, reached_state=LoginState.S0_REDIRECT, response=resp)

        form_data = self._extract_form_inputs(resp.data.decode('utf-8'))
        form_data['username'] = self.test_user.mail_addresses.primary.email
        form_data['password'] = 'Jenka'
        if 'redirect_uri' not in form_data:
            return LoginResult(url=path, reached_state=LoginState.S1_LOGIN_FORM, response=resp)

        cookies = resp.headers.get('Set-Cookie')
        if not cookies:
            return LoginResult(url=path, reached_state=LoginState.S1_LOGIN_FORM, response=resp)

        with self.session_cookie_anon(self.browser) as browser:
            resp = browser.post('/verify', data=form_data, headers={'Cookie': cookies})
            if resp.status_code != 302:
                return LoginResult(url='/verify', reached_state=LoginState.S2_VERIFY, response=resp)

        redirect_loc = self._extract_path_from_response(resp)
        # check that we were sent back to the login screen
        # TODO: verify that we really were logged in
        if not redirect_loc.startswith('/sso/redirect?key='):
            return LoginResult(url='/verify', reached_state=LoginState.S2_VERIFY, response=resp)

        cookies = resp.headers.get('Set-Cookie')
        if not cookies:
            return LoginResult(url='/verify', reached_state=LoginState.S2_VERIFY, response=resp)

        # Save the SSO cookie value
        sso_cookie_val = None
        _re = f'.*{self.app.conf.sso_cookie.key}=(.+?);.*'
        _sso_cookie_re = re.match(_re, cookies)
        if _sso_cookie_re:
            sso_cookie_val = _sso_cookie_re.groups()[0]

        resp = self.browser.get(redirect_loc, headers={'Cookie': cookies})
        if resp.status_code != 200:
            return LoginResult(
                url=redirect_loc,
                sso_cookie_val=sso_cookie_val,
                reached_state=LoginState.S3_REDIRECT_LOGGED_IN,
                response=resp,
            )

        return LoginResult(
            url=redirect_loc, sso_cookie_val=sso_cookie_val, reached_state=LoginState.S5_LOGGED_IN, response=resp
        )

    @staticmethod
    def _extract_form_inputs(res: str) -> Dict[str, Any]:
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

    def parse_saml_authn_response(
        self, response: FlaskResponse, saml2_client: Optional[Saml2Client] = None
    ) -> AuthnResponse:
        _saml2_client = saml2_client if saml2_client is not None else self.saml2_client

        form = self._extract_form_inputs(response.data.decode('utf-8'))
        xmlstr = bytes(form['SAMLResponse'], 'ascii')
        outstanding_queries = self.pysaml2_oq.outstanding_queries()
        return _saml2_client.parse_authn_request_response(xmlstr, BINDING_HTTP_POST, outstanding_queries)

    def get_sso_session(self, sso_cookie_val: str) -> Optional[SSOSession]:
        if sso_cookie_val is None:
            return None
        return self.app.sso_sessions.get_session(b64decode(sso_cookie_val), self.app.userdb)
