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

from eduid_userdb.security import PasswordResetStateDB
from eduid_common.api.app import get_app_config
from eduid_common.api import mail_relay
from eduid_common.api import am, msg
from eduid_common.authn.middleware import AuthnApp
from eduid_webapp.reset_password.settings.common import ResetPasswordConfig

__author__ = 'eperez'


class ResetPasswordApp(AuthnApp):

    def __init__(self, name, config):
        # Init config for common setup
        config = get_app_config(name, config)
        super(ResetPasswordApp, self).__init__(name, config)
        # Init app config
        self.config = ResetPasswordConfig(**config)
        # Init dbs
        self.private_userdb = PasswordResetStateDB(self.config.mongo_uri)
        # Init celery
        msg.init_relay(self)
        am.init_relay(self, 'eduid_reset_password')
        # Initiate external modules


def get_current_app() -> ResetPasswordApp:
    """Teach pycharm about ResetPasswordApp"""
    return current_app  # type: ignore


current_reset_password_app = get_current_app()


def init_reset_password_app(name: str, config: dict) -> ResetPasswordApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :return: the flask app
    """
    app = ResetPasswordApp(name, config)

    # Register views
    from eduid_webapp.reset_password.views import reset_password_views
    app.register_blueprint(reset_password_views, url_prefix=app.config.application_root)

    app.logger.info('{!s} initialized'.format(name))
    return app
