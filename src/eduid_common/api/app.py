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
"""
Define a EduIDApp to create a Flask app and update
it with all attributes common to all eduID services.
"""
import importlib.util
import os
import warnings
from dataclasses import fields, asdict
from typing import Type, Optional, Mapping

from eduid_userdb import UserDB
from flask import Flask
from sys import stderr
from werkzeug.middleware.proxy_fix import ProxyFix

from eduid_common.api.debug import init_app_debug
from eduid_common.api.exceptions import init_exception_handlers, init_sentry
from eduid_common.api.logging import init_logging
from eduid_common.api.middleware import PrefixMiddleware
from eduid_common.api.request import Request
from eduid_common.api.utils import init_template_functions
from eduid_common.config.base import FlaskConfig
from eduid_common.config.exceptions import BadConfiguration
from eduid_common.config.parsers.etcd import EtcdConfigParser
from eduid_common.session.eduid_session import SessionFactory
from eduid_common.stats import NoOpStats, Statsd

DEBUG = os.environ.get('EDUID_APP_DEBUG', False)
if DEBUG:
    stderr.writelines('----- WARNING! EDUID_APP_DEBUG is enabled -----\n')


class EduIDApp(Flask):

    def __init__(self, name: str, config: Mapping = None, init_central_userdb: bool = True, **kwargs):
        super(EduIDApp, self).__init__(name, **kwargs)
        if config is None:
            warnings.warn("config argument should be set to an app class config object",
                          DeprecationWarning)
            return
        # Only try to load the key, value pairs that FlaskConfig expects
        field_names = set(f.name for f in fields(FlaskConfig))
        filtered_config = {k: v for k, v in config.items() if k in field_names}
        # XXX: try except
        self.config = FlaskConfig(**filtered_config)

        if DEBUG:
            init_app_debug(self)

        # Check that SECRET_KEY is set
        if not self.config.secret_key:
            raise BadConfiguration('SECRET_KEY is missing')

        # App setup
        self.wsgi_app = ProxyFix(self.wsgi_app)  # type: ignore
        self.request_class = Request
        self.url_map.strict_slashes = False

        # Set app url prefix to APPLICATION_ROOT
        self.wsgi_app = PrefixMiddleware(self.wsgi_app, prefix=self.config.application_root,  # type: ignore
                                         server_name=self.config.server_name)

        # Initialize shared features
        init_logging(self)
        init_exception_handlers(self)
        init_sentry(self)
        init_template_functions(self)
        self.session_interface = SessionFactory(asdict(self.config))

        stats_host = self.config.stats_host
        if not stats_host:
            self.stats = NoOpStats()
        else:
            stats_port = self.config.stats_port
            self.stats = Statsd(host=stats_host, port=stats_port, prefix=name)

        if init_central_userdb:
            self.central_userdb = UserDB(self.config.mongo_uri, 'eduid_am')

        # Set up generic health check views
        from eduid_common.api.views.status import status_views
        self.register_blueprint(status_views)

    def init_config(self, config_class, config):
        warnings.warn("init_config is deprecated. The configuration is now loaded when instantiating the class.",
                      DeprecationWarning)
        self.config: FlaskConfig = config_class(**config)


# Avoid circular dependency
from eduid_common.authn.middleware import AuthnApp as AuthnAppMiddleware  # TODO: Should maybe be a mixin?


def get_app_config(name: str, config: Optional[dict] = None):
    """
    Get configuration for flask app.

    If config is not provided, retrieve configuration values from etcd.
    If there is an env var LOCAL_CFG_FILE pointing to a file with configuration
    keys, load them as well.
    """
    if config is None:
        config = {}
    # Do not use config from etcd if a config dict is supplied
    if not config:
        # Init etcd config parsers
        common_parser = EtcdConfigParser('/eduid/webapp/common/')
        app_etcd_namespace = os.environ.get('EDUID_CONFIG_NS', '/eduid/webapp/{!s}/'.format(name))
        app_parser = EtcdConfigParser(app_etcd_namespace)
        # Load optional project wide settings
        common_config = common_parser.read_configuration(silent=False)
        if common_config:
            config.update(common_config)
        # Load optional app specific settings
        app_config = app_parser.read_configuration(silent=False)
        if app_config:
            config.update(app_config)

    # Load optional app specific secrets
    secrets_path = os.environ.get('LOCAL_CFG_FILE')
    if secrets_path is not None and os.path.exists(secrets_path):
        spec = importlib.util.spec_from_file_location("secret.settings", secrets_path)
        secret_settings_module = importlib.util.module_from_spec(spec)
        for secret in dir(secret_settings_module):
            if not secret.startswith('_'):
                config[secret.lower()] = getattr(secret_settings_module, secret)
    return config


def eduid_init_app_no_db(name: str, config: dict,
                         config_class: Type[FlaskConfig] = FlaskConfig,
                         app_class: Type[EduIDApp] = AuthnAppMiddleware,
                         app_args: Optional[dict] = None) -> EduIDApp:
    """
    Create and prepare the flask app for eduID APIs with all the attributes
    common to all  apps.

     * Parse and merge configurations
     * Add logging
     * Add db connection
     * Add eduID session
    """
    warnings.warn("eduid_init_app_no_db is deprecated. The app setup is now done when instantiating the class.",
                  DeprecationWarning)
    if app_class is Flask:
        app_class = EduIDApp
    if app_args is None:
        app_args = {}
    app = app_class(name, **app_args)
    # mypy issue: https://github.com/python/mypy/issues/2427
    app.wsgi_app = ProxyFix(app.wsgi_app)  # type: ignore
    app.request_class = Request
    app.url_map.strict_slashes = False

    config = get_app_config(name, config)

    if not isinstance(app, app_class):
        app.__class__ = app_class

    app.init_config(config_class, config)

    if DEBUG:
        app = init_app_debug(app)

    # Check that SECRET_KEY is set
    if not app.config.secret_key:
        raise BadConfiguration('SECRET_KEY is missing')

    # Set app url prefix to APPLICATION_ROOT
    app.wsgi_app = PrefixMiddleware(app.wsgi_app, prefix=app.config.application_root,  # type: ignore
                                    server_name=app.config.server_name)
    # Initialize shared features
    app = init_logging(app)
    app = init_exception_handlers(app)
    app = init_sentry(app)
    app = init_template_functions(app)
    app.session_interface = SessionFactory(app.config)

    stats_host = app.config.stats_host
    if not stats_host:
        app.stats = NoOpStats()
    else:
        stats_port = app.config.stats_port
        app.stats = Statsd(host=stats_host, port=stats_port, prefix=name)

    return app


def eduid_init_app(name: str, config: dict,
                   config_class: Type[FlaskConfig] = FlaskConfig,
                   app_class: Type[EduIDApp] = AuthnAppMiddleware) -> EduIDApp:
    warnings.warn("eduid_init_app_no_db is deprecated. The app setup is now done when instantiating the class.",
                  DeprecationWarning)
    app = eduid_init_app_no_db(name, config=config, config_class=config_class, app_class=app_class)
    app.central_userdb = UserDB(app.config.mongo_uri, 'eduid_am')
    # Set up generic health check views
    from eduid_common.api.views.status import status_views
    app.register_blueprint(status_views)
    return app
