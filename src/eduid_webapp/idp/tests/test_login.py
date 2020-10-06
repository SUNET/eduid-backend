import logging
import os
from typing import Any, Dict

from flask import make_response

from eduid_common.api.app import EduIDBaseApp
from eduid_webapp.idp.settings.common import IdPConfig
from eduid_webapp.idp.tests.test_app import IdPTests
from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client

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
        self.saml2_client = Saml2Client(config_file=self.app.config.pysaml2_config)

    def update_config(self, config):
        config = super().update_config(config)
        config.update({
            'signup_link': 'TEST-SIGNUP-LINK',
            })
        return config

    def test_display_of_login_page(self):
        next_url = '/back-to-test-marker'

        (session_id, info) = self.saml2_client.prepare_for_authenticate(
            entityid=self.idp_entity_id, relay_state=next_url, binding=BINDING_HTTP_REDIRECT,
        )

        # Find first Location tuple
        loc = [_hdr[1] for _hdr in info['headers'] if _hdr[0] == 'Location'][0]
        # It is a complete URL, extract the path from it
        _idx = loc.index('/sso/redirect')
        path = loc[_idx:]

        with self.app.test_request_context(path):
            res = self.app.dispatch_request()

            response = make_response()

            assert response.status_code == 200

            assert self.app.config.signup_link in res

            # the RelayState is present as a hidden form parameter in the login page
            assert next_url in res

