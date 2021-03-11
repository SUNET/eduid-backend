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
from typing import Any, Mapping, Optional, cast

from flask import current_app, render_template, templating

from eduid.common.api.am import AmRelay
from eduid.common.api.app import EduIDBaseApp
from eduid.common.config.parsers import load_config
from eduid.userdb.actions import ActionDB
from eduid.webapp.actions.settings.common import ActionsConfig


class PluginsRegistry(dict):
    def __init__(self, app):
        super(PluginsRegistry, self).__init__()
        for plugin_name in app.conf.action_plugins:
            if plugin_name in self:
                app.logger.warn(f'Duplicate entry point: {plugin_name}')
            else:
                app.logger.debug(f'Registering entry point: {plugin_name}')
                module = import_module(f'eduid.webapp.actions.actions.{plugin_name}')
                self[plugin_name] = getattr(module, 'Plugin')


def _get_tous(app, version=None):
    if version is None:
        version = app.conf.tou_version
    langs = app.conf.available_languages.keys()
    tous = {}
    for lang in langs:
        name = f'tous/tou-{version}-{lang}.txt'
        try:
            tous[lang] = render_template(name)
        except templating.TemplateNotFound:
            app.logger.error(f'ToU template {name} not found')
            pass
    return tous


class ActionsApp(EduIDBaseApp):
    def __init__(self, config: ActionsConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.conf = config

        self.am_relay = AmRelay(config)

        self.actions_db = ActionDB(config.mongo_uri)

        self.plugins = PluginsRegistry(self)
        for plugin in self.plugins.values():
            plugin.includeme(self)

        self.get_tous = types.MethodType(_get_tous, self)


current_actions_app: ActionsApp = cast(ActionsApp, current_app)


def actions_init_app(name: str = 'actions', test_config: Optional[Mapping[str, Any]] = None) -> ActionsApp:
    """
    Create an instance of an eduid actions app.

    Note that we use EduIDBaseApp as the class for the Flask app,
    since the actions app is used unauthenticated.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=ActionsConfig, app_name=name, ns='webapp', test_config=test_config)

    app = ActionsApp(config)

    app.logger.info(f'Init {config.app_name} app...')

    from eduid.webapp.actions.views import actions_views

    app.register_blueprint(actions_views)

    return app
