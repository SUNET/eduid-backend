# -*- coding: utf-8 -*-
#
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

from typing import cast, Dict
from flask import current_app

from eduid_common.api import mail_relay
from eduid_common.api import am, msg
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_webapp.{{cookiecutter.directory_name}}.settings.common import {{cookiecutter.class_name}}Config

__author__ = '{{cookiecutter.author}}'


class {{cookiecutter.class_name}}App(AuthnApp):

    def __init__(self, name: str, config: Dict, **kwargs):
        # Initialise type of self.config before any parent class sets a precedent to mypy
        self.config = {{cookiecutter.class_name}}Config.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)
        # cast self.config because sometimes mypy thinks it is a FlaskConfig after super().__init__()
        self.config: {{cookiecutter.class_name}}Config = cast({{cookiecutter.class_name}}Config, self.config)
        # Init dbs
        self.private_userdb = {{cookiecutter.class_name}}UserDB(self.config.mongo_uri)
        # Init celery
        msg.init_relay(self)
        am.init_relay(self, 'eduid_{{cookiecutter.directory_name}}')
        # Initiate external modules


current_{{cookiecutter.directory_name}}_app = cast({{cookiecutter.class_name}}App, current_app)


def init_{{cookiecutter.directory_name}}_app(name: str, config: Dict) -> {{cookiecutter.class_name}}App:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :return: the flask app
    """
    app = {{cookiecutter.class_name}}App(name, config)

    # Register views
    from eduid_webapp.{{cookiecutter.directory_name}}.views import {{cookiecutter.directory_name}}_views
    app.register_blueprint({{cookiecutter.directory_name}}_views)

    app.logger.info('{!s} initialized'.format(name))
    return app
