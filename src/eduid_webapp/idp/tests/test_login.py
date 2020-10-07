import logging
import os
import re
from typing import Any, Dict, Mapping, Sequence

from flask import Response as FlaskResponse
from flask import make_response
from mock import patch
from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client

from eduid_common.api.app import EduIDBaseApp
from eduid_common.authn.utils import get_saml2_config

from eduid_webapp.idp.settings.common import IdPConfig
from eduid_webapp.idp.tests.test_app import IdPTests

logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


class IdPTestApp(EduIDBaseApp):
    def __init__(self, name: str, config: Dict[str, Any], **kwargs):
        self.config = IdPConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)


class IdPAPITestBase(IdPTests):
    def setUp(self):
        super().setUp()
        self.idp_entity_id = 'https://unittest-idp.example.edu/idp.xml'
        sp_config = get_saml2_config(self.app.config.pysaml2_config)
        self.saml2_client = Saml2Client(config=sp_config)

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

        with self.app.test_request_context(path):
            res = self.app.dispatch_request()

            response = make_response()

        assert response.status_code == 200
        assert self.app.config.signup_link in res

        # the RelayState is present as a hidden form parameter in the login page
        assert next_url in res

    def test_submitting_wrong_credentials(self):
        next_url = '/back-to-test-marker'

        res = self._try_login(next_url)

        redirect_loc = self._extract_path_from_response(res)
        # check that we were sent back to the login screen
        # TODO: verify that we really were not logged in
        assert redirect_loc.startswith('/sso/redirect?SAMLRequest=')

    def test_submitting_correct_credentials(self):
        next_url = '/back-to-test-marker'

        # Patch the VCCSClient so we do not need a vccs server
        from vccs_client import VCCSClient

        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            resp = self._try_login(next_url)

        redirect_loc = self._extract_path_from_response(resp)
        # check that we were sent back to the login screen
        # TODO: verify that we really were logged in
        assert redirect_loc.startswith('/sso/redirect?key=')

        cookies = resp.headers.get('Set-Cookie')

        resp = self.browser.get(redirect_loc, headers={'Cookie': cookies})
        assert resp.status_code == 200

    def _try_login(self, next_url: str) -> FlaskResponse:
        (session_id, info) = self.saml2_client.prepare_for_authenticate(
            entityid=self.idp_entity_id, relay_state=next_url, binding=BINDING_HTTP_REDIRECT,
        )
        path = self._extract_path_from_info(info)
        with self.session_cookie_anon(self.browser) as browser:
            resp = browser.get(path)
            assert resp.status_code == 200

        form_data = self._extract_form_inputs(resp.data.decode('utf-8'))
        del form_data['key']  # test if key is really necessary
        form_data['username'] = self.test_user.mail_addresses.primary.email
        form_data['password'] = 'Jenka'
        assert 'redirect_uri' in form_data

        cookies = resp.headers.get('Set-Cookie')

        with self.session_cookie_anon(self.browser) as browser:
            resp = browser.post('/verify', data=form_data, headers={'Cookie': cookies})
            assert resp.status_code == 302

        return resp

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
