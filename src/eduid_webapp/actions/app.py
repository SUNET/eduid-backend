# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 NORDUnet A/S
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

import types
from importlib import import_module
from typing import cast

from flask import current_app, render_template, templating

from eduid_common.api import am
from eduid_common.api.app import EduIDBaseApp
from eduid_userdb.actions import ActionDB

from eduid_webapp.actions.settings.common import ActionsConfig


class PluginsRegistry(dict):
    def __init__(self, app):
        super(PluginsRegistry, self).__init__()
        for plugin_name in app.config.action_plugins:
            if plugin_name in self:
                app.logger.warn("Duplicate entry point: %s" % plugin_name)
            else:
                app.logger.debug("Registering entry point: %s" % plugin_name)
                module = import_module('eduid_webapp.actions.actions.{}'.format(plugin_name))
                self[plugin_name] = getattr(module, 'Plugin')


def _get_tous(app, version=None):
    if version is None:
        version = app.config.tou_version
    langs = app.config.available_languages.keys()
    tous = {}
    for lang in langs:
        name = 'tous/tou-{}-{}.txt'.format(version, lang)
        try:
            tous[lang] = render_template(name)
        except templating.TemplateNotFound:
            app.logger.error('TOU template {} not found'.format(name))
            pass
    return tous


class ActionsApp(EduIDBaseApp):
    def __init__(self, name: str, config: dict, **kwargs):
        # Initialise type of self.config before any parent class sets a precedent to mypy
        self.config = ActionsConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)
        # cast self.config because sometimes mypy thinks it is a FlaskConfig after super().__init__()
        self.config: ActionsConfig = cast(ActionsConfig, self.config)  # type: ignore

        from eduid_webapp.actions.views import actions_views

        self.register_blueprint(actions_views)

        am.init_relay(self, f'eduid_{name}')

        self.actions_db = ActionDB(self.config.mongo_uri)

        self.plugins = PluginsRegistry(self)
        for plugin in self.plugins.values():
            plugin.includeme(self)

        self.get_tous = types.MethodType(_get_tous, self)


current_actions_app: ActionsApp = cast(ActionsApp, current_app)


def actions_init_app(name: str, config: dict) -> ActionsApp:
    """
    Create an instance of an eduid actions app.

    Note that we use EduIDBaseApp as the class for the Flask app,
    since the actions app is used unauthenticated.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases
    """

    app = ActionsApp(name, config)

    app.logger.info(f'Init {name} app...')

    return app
