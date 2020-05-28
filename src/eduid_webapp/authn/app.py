#
# Copyright (c) 2016 NORDUnet A/S
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
from typing import cast

from flask import current_app

from eduid_common.api.app import EduIDBaseApp
from eduid_common.authn.utils import get_saml2_config

from eduid_webapp.authn.settings.common import AuthnConfig


class AuthnApp(EduIDBaseApp):
    def __init__(self, name: str, config: dict, **kwargs):
        # Initialise type of self.config before any parent class sets a precedent to mypy
        self.config = AuthnConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)
        # cast self.config because sometimes mypy thinks it is a FlaskConfig after super().__init__()
        self.config: AuthnConfig = cast(AuthnConfig, self.config)  # type: ignore

        self.saml2_config = get_saml2_config(self.config.saml2_settings_module)

        from eduid_webapp.authn.views import authn_views

        self.register_blueprint(authn_views)


def get_current_app() -> AuthnApp:
    """Teach pycharm about AuthnApp"""
    return current_app  # type: ignore


current_authn_app = get_current_app()


def authn_init_app(name: str, config: dict) -> AuthnApp:
    """
    Create an instance of an authentication app.

    :param name: The name of the instance, it will affect the configuration file
                 loaded from the filesystem.
    :param config: any additional configuration settings. Specially useful
                   in test cases
    """
    app = AuthnApp(name, config)

    app.logger.info(f'Init {name} app...')

    return app
