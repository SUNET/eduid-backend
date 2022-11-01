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
from typing import Any, Dict, Mapping, Optional, cast

from captcha.image import ImageCaptcha
from flask import current_app

from eduid.common.clients import SCIMClient
from eduid.common.config.exceptions import BadConfiguration
from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.mail_relay import MailRelay
from eduid.queue.db.message import MessageDB
from eduid.userdb.logs import ProofingLog
from eduid.userdb.signup import SignupInviteDB, SignupUserDB
from eduid.webapp.common.api import translation
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.signup.settings.common import SignupConfig


class SignupApp(EduIDBaseApp):
    def __init__(self, config: SignupConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.conf = config

        self.am_relay = AmRelay(config)
        self.mail_relay = MailRelay(config)

        self.captcha_image_generator = ImageCaptcha(
            height=self.conf.captcha_height,
            width=self.conf.captcha_width,
            fonts=self.conf.captcha_fonts,
            font_sizes=self.conf.captcha_font_size,
        )

        self.scim_clients: Dict[str, SCIMClient] = {}

        self.private_userdb = SignupUserDB(config.mongo_uri, auto_expire=config.private_userdb_auto_expire)
        self.proofing_log = ProofingLog(config.mongo_uri)
        self.invite_db = SignupInviteDB(config.mongo_uri)
        self.messagedb = MessageDB(config.mongo_uri)

    def get_scim_client_for(self, data_owner: str) -> SCIMClient:
        if self.conf.gnap_auth_data is None or self.conf.scim_api_url is None:
            raise BadConfiguration("No auth server configuration available")

        if data_owner not in self.scim_clients:
            access_request = [{"type": "scim-api", "scope": data_owner}]
            client_auth_data = self.conf.gnap_auth_data.copy(update={"access": access_request})
            self.scim_clients[data_owner] = SCIMClient(scim_api_url=self.conf.scim_api_url, auth_data=client_auth_data)
        return self.scim_clients[data_owner]


current_signup_app: SignupApp = cast(SignupApp, current_app)


def signup_init_app(name: str = "signup", test_config: Optional[Mapping[str, Any]] = None) -> SignupApp:
    """
    Create an instance of an eduid signup app.

    Note that we use EduIDBaseApp as the class for the Flask app,
    since obviously the signup app is used unauthenticated.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config. Used in test cases.
    """
    config = load_config(typ=SignupConfig, app_name=name, ns="webapp", test_config=test_config)

    app = SignupApp(config)

    app.logger.info(f"Init {app}...")

    from eduid.webapp.signup.views import signup_views

    app.register_blueprint(signup_views)

    translation.init_babel(app)

    return app
