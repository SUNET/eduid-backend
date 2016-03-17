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

import saml2
from flask import request, session, Response

from eduid_common.api.testing import EduidAPITestCase
from eduid_common.authn.utils import get_location
from eduid_common.authn.eduid_saml2 import get_authn_request
from eduid_webapp.authn.app import authn_init_app

HERE = os.path.abspath(os.path.dirname(__file__))


class AuthnAPITestCase(EduidAPITestCase):

    def update_config(self, config):
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        saml_config = os.path.join(HERE, 'saml2_settings.py')
        config.update({
            'SAML2.LOGIN_REDIRECT_URL': '/',
            'SAML2.SETTINGS_MODULE': saml_config,
            })
        return config

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return authn_init_app('testing', config)

    def test_authn(self):
        with self.app.test_request_context('/login', method='GET'):
            resp = self.app.dispatch_request()
            authn_req = get_location(get_authn_request(self.app.config,
                                                       session, '/', None))
            idp_url = authn_req.split('?')[0]
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.location.startswith(idp_url))
