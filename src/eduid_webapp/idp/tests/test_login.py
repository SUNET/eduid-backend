import logging
import os
import re
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple
from saml2.authn_context import requested_authn_context
from flask import Response as FlaskResponse
from flask import make_response
from mock import patch
from saml2.samlp import RequestedAuthnContext

from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client

from eduid_common.api.app import EduIDBaseApp
from eduid_common.authn.utils import get_saml2_config
from vccs_client import VCCSClient

from eduid_webapp.idp.settings.common import IdPConfig
from eduid_webapp.idp.tests.test_app import IdPTests

logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


class LoginState(Enum):
    S0_REDIRECT = 'redirect'
    S1_LOGIN_FORM = 'login-form'
    S2_VERIFY = 'verify'
    S3_REDIRECT_LOGGED_IN = 'redirect-logged-in'
    S4_REDIRECT_TO_ACS = 'redirect-to-acs'
    S5_LOGGED_IN = 'logged-in'


class IdPTestApp(EduIDBaseApp):
    def __init__(self, name: str, config: Dict[str, Any], **kwargs):
        self.config = IdPConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)


class IdPAPITestBase(IdPTests):
    def setUp(self):
        super().setUp()
        self.idp_entity_id = 'https://unittest-idp.example.edu/idp.xml'
        self.relay_state = 'test-fest'
        self.sp_config = get_saml2_config(self.app.config.pysaml2_config, name='SP_CONFIG')
        self.saml2_client = Saml2Client(config=self.sp_config)

    def update_config(self, config):
        config = super().update_config(config)
        config.update({'signup_link': 'TEST-SIGNUP-LINK', 'log_level': 'DEBUG'})
        return config

    def test_display_of_login_page(self):
        next_url = '/back-to-test-marker'

        (session_id, info) = self.saml2_client.prepare_for_authenticate(
            entityid=self.idp_entity_id, relay_state=next_url, binding=BINDING_HTTP_REDIRECT,
        )

        path = self._extract_path_from_info(info)

        response = self.browser.get(path)
        body = response.data.decode('utf-8')

        assert response.status_code == 200
        assert self.app.config.signup_link in body

        # the RelayState is present as a hidden form parameter in the login page
        assert next_url in body

    def test_submitting_wrong_credentials(self):
        reached_state, resp = self._try_login()

        assert reached_state == LoginState.S2_VERIFY

        # check that we were sent back to the login screen
        redirect_loc = self._extract_path_from_response(resp)
        assert redirect_loc.startswith('/sso/redirect?SAMLRequest=')

    def test_successful_authentication(self):
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            reached_state, resp = self._try_login()

        assert reached_state == LoginState.S5_LOGGED_IN

    def test_terminated_user(self):
        user = self.amdb.get_user_by_eppn(self.test_user.eppn)
        user.terminated = True
        self.amdb.save(user)

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            reached_state, resp = self._try_login()

        assert reached_state == LoginState.S3_REDIRECT_LOGGED_IN
        cookie = resp.headers['Set-Cookie']
        assert 'idpauthn=;' in cookie
        assert 'expires=Thu, 01-Jan-1970 00:00:00 GMT' in cookie

    def test_with_unknown_sp(self):
        sp_config = get_saml2_config(self.app.config.pysaml2_config, name='UNKNOWN_SP_CONFIG')
        saml2_client = Saml2Client(config=sp_config)

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            reached_state, resp = self._try_login(saml2_client=saml2_client)

        assert reached_state == LoginState.S3_REDIRECT_LOGGED_IN
        assert b'SAML error: Unknown Service Provider' in resp.data

    def test_sso_to_unknown_sp(self):
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            reached_state, resp = self._try_login()

        assert reached_state == LoginState.S5_LOGGED_IN

        sp_config = get_saml2_config(self.app.config.pysaml2_config, name='UNKNOWN_SP_CONFIG')
        saml2_client = Saml2Client(config=sp_config)

        # Don't patch VCCS here to ensure a SSO is done, not a password authentication
        reached_state, resp = self._try_login(saml2_client=saml2_client)

        assert reached_state == LoginState.S0_REDIRECT
        assert b'SAML error: Unknown Service Provider' in resp.data
        cookies = resp.headers['Set-Cookie']
        # Ensure the pre-existing idpauthn cookie wasn't touched
        assert 'idpauthn' not in cookies

    def test_with_authncontext(self):
        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            # request MFA, but the test user does not have any MFA credentials
            req_authn_context = requested_authn_context('https://refeds.org/profile/mfa', comparison='exact')
            reached_state, response = self._try_login(authn_context=req_authn_context)

        assert reached_state == LoginState.S3_REDIRECT_LOGGED_IN
        assert b'Access to the requested service could not be granted.' in response.data

    def _try_login(self, saml2_client: Optional[Saml2Client] = None, authn_context=None) -> Tuple[LoginState, FlaskResponse]:
        """
        Try logging in to the IdP.

        :return: Information about how far we got (reached LoginState) and the last response instance.
        """
        _saml2_client = saml2_client if saml2_client is not None else self.saml2_client
        (session_id, info) = _saml2_client.prepare_for_authenticate(
            entityid=self.idp_entity_id, relay_state=self.relay_state, binding=BINDING_HTTP_REDIRECT,
            requested_authn_context=authn_context,
        )
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
        # It is a complete URL, extract the path from it (8 is to skip over slashes in https://)
        _idx = loc[8:].index('/')
        path = loc[8 + _idx :]
        return path
