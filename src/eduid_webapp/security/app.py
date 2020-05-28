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

from eduid_common.api import am, mail_relay, msg, translation
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_common.authn.utils import no_authn_views
from eduid_userdb.authninfo import AuthnInfoDB
from eduid_userdb.logs import ProofingLog
from eduid_userdb.security import PasswordResetStateDB, SecurityUserDB

from eduid_webapp.security.settings.common import SecurityConfig


class SecurityApp(AuthnBaseApp):
    def __init__(self, name: str, config: dict, **kwargs):
        # Initialise type of self.config before any parent class sets a precedent to mypy
        self.config = SecurityConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)
        # cast self.config because sometimes mypy thinks it is a FlaskConfig after super().__init__()
        self.config: SecurityConfig = cast(SecurityConfig, self.config)  # type: ignore

        from eduid_webapp.security.views.security import security_views
        from eduid_webapp.security.views.u2f import u2f_views
        from eduid_webapp.security.views.webauthn import webauthn_views
        from eduid_webapp.security.views.reset_password import reset_password_views

        self.register_blueprint(security_views)
        self.register_blueprint(u2f_views)
        self.register_blueprint(webauthn_views)
        self.register_blueprint(reset_password_views)

        # Register view path that should not be authorized
        no_authn_views(self, ['/reset-password.*'])

        am.init_relay(self, f'eduid_{name}')
        msg.init_relay(self)
        mail_relay.init_relay(self)
        translation.init_babel(self)

        self.private_userdb = SecurityUserDB(self.config.mongo_uri)
        self.authninfo_db = AuthnInfoDB(self.config.mongo_uri)
        self.password_reset_state_db = PasswordResetStateDB(self.config.mongo_uri)
        self.proofing_log = ProofingLog(self.config.mongo_uri)


current_security_app: SecurityApp = cast(SecurityApp, current_app)


def security_init_app(name: str, config: dict) -> SecurityApp:
    """
    Create an instance of an eduid security (passwords) app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases
    """
    app = SecurityApp(name, config)

    app.logger.info(f'Init {name} app...')

    return app
