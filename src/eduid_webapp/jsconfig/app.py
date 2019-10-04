# -*- coding: utf-8 -*-
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
from typing import cast

from eduid_common.api.app import eduid_init_app_no_db
from eduid_common.authn.utils import no_authn_views
from eduid_common.config.app import EduIDApp
from eduid_webapp.jsconfig.settings.common import JSConfigConfig
from eduid_webapp.jsconfig.settings.front import FrontConfig


class JSConfigApp(EduIDApp):

    def __init__(self, *args, **kwargs):
        super(JSConfigApp, self).__init__(*args, **kwargs)
        self.config: FrontConfig = cast(FrontConfig, self.config)


def jsconfig_init_app(name: str, config: dict) -> JSConfigApp:
    """
    Create an instance of an eduid jsconfig data app.

    First, it will load the configuration from jsconfig.settings.common
    then any settings given in the `config` param.

    Then, the app instance will be updated with common stuff by `eduid_init_app`,
    all needed blueprints will be registered with it.
    """

    app = eduid_init_app_no_db(name, config,
                               config_class=JSConfigConfig,
                               app_class=JSConfigApp)

    from eduid_webapp.jsconfig.views import jsconfig_views
    app.register_blueprint(jsconfig_views)

    # Register view path that should not be authorized
    no_auth_paths = [
        '/get-bundle',
        '/signup/config'
    ]
    app = no_authn_views(app, no_auth_paths)

    app.logger.info('Init {} app...'.format(name))
    return app
