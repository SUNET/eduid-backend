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

from eduid_common.api.config import APIConfigParser


class AuthnConfigParser(APIConfigParser):
    """
    """

    section = 'app:authn'

    def __init__(self, config_file_name, config_environment_variable=None):
        super(APIConfigParser, self).__init__(config_file_name,
                                              config_environment_variable)
        self.known_special_keys.update({
            'saml2.login_redirect_url': (self.read_setting_from_env, '/'),
            'saml2.settings_module': (self.read_setting_from_env,
                                      'src/eduid_webapp/authn/tests/saml2_settings.py'),
            'saml2.logout_redirect_url': (self.read_setting_from_env, 'http://html.docker/'),
            # The attribute released by the IdP that we should use to locate the user logging in.
            'saml2.user_main_attribute': (self.read_setting_from_env, 'eduPersonPrincipalName'),
            'saml2.strip_saml_user_suffix': (self.read_setting_from_env, '@local.eduid.se'),
            })
