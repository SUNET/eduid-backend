# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 NORDUnet A/S
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
from importlib import import_module
import types

from flask import Flask, render_template, templating

from eduid_common.api.app import eduid_init_app
from eduid_common.api import am
from eduid_common.config.app import EduIDApp
from eduid_userdb.actions import ActionDB
from eduid_webapp.actions.settings.common import ActionsConfig


class PluginsRegistry(dict):

    def __init__(self, app):
        super(PluginsRegistry, self).__init__()
        for plugin_name in app.config.get('ACTION_PLUGINS', []):
            if plugin_name in self:
                app.logger.warn("Duplicate entry point: %s" % plugin_name)
            else:
                app.logger.debug("Registering entry point: %s" % plugin_name)
                module = import_module('eduid_webapp.actions.actions.{}'.format(plugin_name))
                self[plugin_name] = getattr(module, 'Plugin')


def _get_tous(app, version=None):
    if version is None:
        version = app.config.get('TOU_VERSION')
    langs = app.config.get('AVAILABLE_LANGUAGES').keys()
    tous = {}
    for lang in langs:
        name = 'tous/tou-{}-{}.txt'.format(version, lang)
        try:
            tous[lang] = render_template(name)
        except templating.TemplateNotFound:
            app.logger.error('TOU template {} not found'.format(name))
            pass
    return tous


class ActionsApp(EduIDApp):

    def __init__(self, *args, **kwargs):
        super(ActionsApp, self).__init__(*args, **kwargs)
        self.config: ActionsConfig = cast(ActionsConfig, self.config)
                

def actions_init_app(name, config):
    """
    Create an instance of an eduid actions app.

    First, it will load the configuration from actions.settings.common
    then any settings given in the `config` param.

    Then, the app instance will be updated with common stuff by `eduid_init_app`,
    all needed blueprints will be registered with it,
    and finally the app is configured with the necessary db connections.

    Note that we use UnAuthnApp as the class for the Flask app,
    since the actions app is used unauthenticated.

    :param name: The name of the instance, it will affect the configuration loaded.
    :type name: str
    :param config: any additional configuration settings. Specially useful
                   in test cases
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """

    app = eduid_init_app(name, config, config_class=ActionsConfig, app_class=EduIDApp)

    from eduid_webapp.actions.views import actions_views
    app.register_blueprint(actions_views)

    app = am.init_relay(app, 'eduid_actions')

    app.actions_db = ActionDB(app.config.mongo_uri)

    app.plugins = PluginsRegistry(app)
    for plugin in app.plugins.values():
        plugin.includeme(app)

    app.get_tous = types.MethodType(_get_tous, app)

    app.logger.info('Init {} app...'.format(name))

    return app
