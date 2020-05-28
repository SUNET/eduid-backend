# -*- coding: utf-8 -*-
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
from eduid_common.authn.utils import no_authn_views

from eduid_webapp.jsconfig.settings.common import JSConfigConfig


class JSConfigApp(EduIDBaseApp):
    def __init__(self, name: str, config: dict, **kwargs):

        kwargs['init_central_userdb'] = False
        kwargs['host_matching'] = True
        kwargs['static_folder'] = None
        kwargs['subdomain_matching'] = True

        # Initialise type of self.config before any parent class sets a precedent to mypy
        self.config = JSConfigConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)
        # cast self.config because sometimes mypy thinks it is a FlaskConfig after super().__init__()
        self.config: JSConfigConfig = cast(JSConfigConfig, self.config)  # type: ignore

        if not self.testing:
            self.url_map.host_matching = False

        from eduid_webapp.jsconfig.views import jsconfig_views

        self.register_blueprint(jsconfig_views)

        # Register view path that should not be authorized
        no_auth_paths = ['/get-bundle', '/signup/config']
        no_authn_views(self, no_auth_paths)


current_jsconfig_app: JSConfigApp = cast(JSConfigApp, current_app)


def jsconfig_init_app(name: str, config: dict) -> JSConfigApp:
    """
    Create an instance of an eduid jsconfig data app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases
    """

    app = JSConfigApp(name, config)

    app.logger.info(f'Init {name} app...')

    return app
