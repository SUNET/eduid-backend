# -*- coding: utf-8 -*-

from __future__ import absolute_import

from eduid_common.api.app import eduid_init_app
from eduid_common.api import am, msg

__author__ = '{{cookiecutter.author}}'


def init_{{cookiecutter.directory_name}}_app(name, config=None):
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :type name: str
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """

    app = eduid_init_app(name, config)

    # Register views
    from eduid_webapp.{{cookiecutter.directory_name}}.views import {{cookiecutter.directory_name}}_views
    app.register_blueprint({{cookiecutter.directory_name}}_views, url_prefix=app.config.get('APPLICATION_ROOT', None))

    # Init dbs

    # Init celery
    app = msg.init_relay(app)
    app = am.init_relay(app, 'eduid_{{cookiecutter.directory_name}}')

    app.logger.info('{!s} initialized'.format(name))
    return app
