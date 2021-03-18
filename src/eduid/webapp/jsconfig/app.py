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
from typing import Any, Mapping, Optional, cast

from flask import current_app

from eduid.common.api.app import EduIDBaseApp
from eduid.common.authn.utils import no_authn_views
from eduid.common.config.base import FlaskConfig
from eduid.common.config.parsers import load_config
from eduid.webapp.jsconfig.settings.common import JSConfigConfig
from eduid.webapp.jsconfig.settings.front import FrontConfig


class JSConfigApp(EduIDBaseApp):
    def __init__(self, config: JSConfigConfig, front_config: FrontConfig, **kwargs):

        kwargs['init_central_userdb'] = False
        kwargs['host_matching'] = True
        kwargs['static_folder'] = None
        kwargs['subdomain_matching'] = True

        super().__init__(config, **kwargs)

        self.conf = config
        self.front_conf = front_config

        if self.testing is False:
            self.url_map.host_matching = False


current_jsconfig_app: JSConfigApp = cast(JSConfigApp, current_app)


def jsconfig_init_app(name: str = 'jsconfig', test_config: Optional[Mapping[str, Any]] = None) -> JSConfigApp:
    """
    Create an instance of an eduid jsconfig data app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=JSConfigConfig, app_name=name, ns='webapp', test_config=test_config)
    front_config = load_config(typ=FrontConfig, app_name='jsapps', ns='webapp', test_config=test_config)

    app = JSConfigApp(config, front_config)

    app.logger.info(f'Init {app}...')

    from eduid.webapp.jsconfig.views import jsconfig_views

    app.register_blueprint(jsconfig_views)

    # Register view path that should not be authorized
    no_auth_paths = ['/get-bundle', '/signup/config']
    no_authn_views(config, no_auth_paths)

    return app
