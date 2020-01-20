# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 SUNET
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

from eduid_userdb.authninfo import AuthnInfoDB
from eduid_userdb.reset_password import ResetPasswordUserDB, ResetPasswordStateDB
from eduid_userdb.logs import ProofingLog
from eduid_common.api import translation
from eduid_common.api.app import get_app_config
from eduid_common.api import mail_relay
from eduid_common.api import am, msg
from eduid_common.api import mail_relay
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_common.authn.utils import no_authn_views
from eduid_webapp.reset_password.settings.common import ResetPasswordConfig

__author__ = 'eperez'


class ResetPasswordApp(AuthnBaseApp):

    def __init__(self, name: str, config: dict, **kwargs):

        super(ResetPasswordApp, self).__init__(name, ResetPasswordConfig, config, **kwargs)

        # Register views
        from eduid_webapp.reset_password.views.reset_password import reset_password_views
        from eduid_webapp.reset_password.views.change_password import change_password_views
        self.register_blueprint(change_password_views)
        self.register_blueprint(reset_password_views)

        # Register view path that should not be authorized
        self = no_authn_views(self, [r'/reset.*'])

        # Init celery
        msg.init_relay(self)
        am.init_relay(self, 'eduid_reset_password')
        mail_relay.init_relay(self)
        translation.init_babel(self)

        # Init dbs
        self.private_userdb = ResetPasswordUserDB(self.config.mongo_uri)
        self.password_reset_state_db = ResetPasswordStateDB(self.config.mongo_uri)
        self.proofing_log = ProofingLog(self.config.mongo_uri)
        self.authninfo_db = AuthnInfoDB(self.config.mongo_uri)


current_reset_password_app: ResetPasswordApp = cast(ResetPasswordApp, current_app)


def init_reset_password_app(name: str, config: dict) -> ResetPasswordApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    """
    app = ResetPasswordApp(name, config)

    app.logger.info(f'Init {name} app...')

    return app
