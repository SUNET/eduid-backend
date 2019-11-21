# -*- coding: utf-8 -*-

from typing import cast
from flask import current_app

from eduid_common.api.app import eduid_init_app
from eduid_common.api import mail_relay
from eduid_common.api import am, msg
from eduid_common.authn.middleware import AuthnApp
from eduid_webapp.{{cookiecutter.directory_name}}.settings.common import {{cookiecutter.class_name}}Config

__author__ = '{{cookiecutter.author}}'


class {{cookiecutter.class_name}}App(AuthnApp):

    def __init__(self, name, config):
        # Init config for common setup
        config = get_app_config(name, config)
        super({{cookiecutter.class_name}}App, self).__init__(name, config)
        # Init app config
        self.config = {{cookiecutter.class_name}}Config(**config)
        # Init dbs
        self.private_userdb = {{cookiecutter.class_name}}UserDB(self.config.mongo_uri)
        # Init celery
        msg.init_relay(self)
        am.init_relay(self, 'eduid_{{cookiecutter.directory_name}}')
        # Initiate external modules


def get_current_app() -> {{cookiecutter.class_name}}App:
    """Teach pycharm about {{cookiecutter.class_name}}App"""
    return current_app  # type: ignore


current_{{cookiecutter.directory_name}}_app = get_current_app()


def init_{{cookiecutter.directory_name}}_app(name: str, config: dict) -> {{cookiecutter.class_name}}App:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :return: the flask app
    """
    app = {{cookiecutter.class_name}}App(name, config)

    # Register views
    from eduid_webapp.{{cookiecutter.directory_name}}.views import {{cookiecutter.directory_name}}_views
    app.register_blueprint({{cookiecutter.directory_name}}_views, url_prefix=app.config.application_root)

    app.logger.info('{!s} initialized'.format(name))
    return app
