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

from __future__ import absolute_import

from typing import cast

from flask import current_app

from eduid_common.api.app import eduid_init_app
from eduid_common.api import mail_relay
from eduid_common.api import am
from eduid_common.api import translation
from eduid_common.config.app import EduIDApp
from eduid_userdb.signup import SignupUserDB
from eduid_userdb.logs import ProofingLog
from eduid_webapp.signup.settings.common import SignupConfig


class SignupApp(EduIDApp):

    def __init__(self, *args, **kwargs):
        super(SignupApp, self).__init__(*args, **kwargs)
        self.config: SignupConfig = cast(SignupConfig, self.config)


current_signup_app: SignupApp = cast(SignupApp, current_app)


def signup_init_app(name, config):
    """
    Create an instance of an eduid signup app.

    First, it will load the configuration from signup.settings.common
    then any settings given in the `config` param.

    Then, the app instance will be updated with common stuff by `eduid_init_app`,
    all needed blueprints will be registered with it,
    and finally the app is configured with the necessary db connections.

    Note that we use UnAuthnApp as the class for the Flask app,
    since obviously the signup app is used unauthenticated.

    :param name: The name of the instance, it will affect the configuration loaded.
    :type name: str
    :param config: any additional configuration settings. Specially useful
                   in test cases
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """

    app = eduid_init_app(name, config,
                         config_class=SignupConfig,
                         app_class=SignupApp)

    from eduid_webapp.signup.views import signup_views
    app.register_blueprint(signup_views)

    app = am.init_relay(app, 'eduid_signup')
    app = mail_relay.init_relay(app)
    app = translation.init_babel(app)

    app.private_userdb = SignupUserDB(app.config.mongo_uri, 'eduid_signup')
    app.proofing_log = ProofingLog(app.config.mongo_uri)

    app.logger.info('Init {} app...'.format(name))

    return app
