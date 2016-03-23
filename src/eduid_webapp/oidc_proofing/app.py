# -*- coding: utf-8 -*-

from __future__ import absolute_import
from flask import Flask
from eduid_common.api.app import eduid_init_app

__author__ = 'lundberg'


def oidc_proofing_init_app(name, config):
    """
    Create an instance of an oidc proofing app.

    First, it will load the configuration from settings.common then any file specified by  OIDC_PROOFING_SETTINGS and
    lastly update it with any settings given in the `config` param.

    Then, the app instance will be updated with common stuff by `eduid_init_app`,
    and finally all needed blueprints will be registered with it.

    :param name: The name of the instance, it will affect the configuration file
                 loaded from the filesystem.
    :type name: str
    :param config: any additional configuration settings. Specially useful
                   in test cases
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """

    app = Flask(name)
    app.config.from_object('eduid_webapp.oidc_proofing.settings.common')
    app.config.from_envvar('OIDC_PROOFING_SETTINGS', silent=True)
    app.config.update(config)
    app = eduid_init_app(app)

    from eduid_webapp.oidc_proofing.views import oidc_proofing_views
    app.register_blueprint(oidc_proofing_views)

    return app
