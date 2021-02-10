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
#     3. Neither the name of the SUNET nor the names of its
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

from eduid_common.api import am, mail_relay, msg, translation
from eduid_common.api.am import AmRelay
from eduid_common.api.app import EduIDBaseApp
from eduid_common.api.mail_relay import MailRelay
from eduid_common.api.msg import MsgRelay
from eduid_common.config.base import FlaskConfig
from eduid_common.config.parsers import load_config
from eduid_userdb.authninfo import AuthnInfoDB
from eduid_userdb.logs import ProofingLog
from eduid_userdb.reset_password import ResetPasswordStateDB, ResetPasswordUserDB

from eduid_webapp.reset_password.settings.common import ResetPasswordConfig

__author__ = 'eperez'


class ResetPasswordApp(EduIDBaseApp):
    def __init__(self, config: ResetPasswordConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.conf = config

        # Init celery
        self.msg_relay = MsgRelay(config)
        self.am_relay = AmRelay(config)
        self.mail_relay = MailRelay(config)

        # Init dbs
        self.private_userdb = ResetPasswordUserDB(self.conf.mongo_uri)
        self.password_reset_state_db = ResetPasswordStateDB(self.conf.mongo_uri)
        self.proofing_log = ProofingLog(self.conf.mongo_uri)
        self.authninfo_db = AuthnInfoDB(self.conf.mongo_uri)


current_reset_password_app: ResetPasswordApp = cast(ResetPasswordApp, current_app)


def init_reset_password_app(
    name: str = 'reset_password', test_config: Optional[Mapping[str, Any]] = None
) -> ResetPasswordApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config. Used in tests.
    """
    config = load_config(typ=ResetPasswordConfig, app_name=name, ns='webapp', test_config=test_config)

    app = ResetPasswordApp(config)

    app.logger.info(f'Init {app}...')

    # Register views
    from eduid_webapp.reset_password.views.reset_password import reset_password_views

    app.register_blueprint(reset_password_views)

    translation.init_babel(app)

    return app
