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
Define a `eduid_init_app` function to create a Flask app and update
it with all attributes common to all eduID services.
"""

import os
from sys import stderr
from typing import Type, cast

from flask import Config, Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from eduid_common.api.debug import dump_config
from eduid_common.api.exceptions import init_exception_handlers, init_sentry
from eduid_common.api.logging import init_logging
from eduid_common.api.middleware import PrefixMiddleware
from eduid_common.api.request import Request
from eduid_common.api.utils import init_template_functions
from eduid_common.authn.middleware import AuthnApp
from eduid_common.config.app import EduIDApp
from eduid_common.config.base import FlaskConfig
from eduid_common.config.exceptions import BadConfiguration
from eduid_common.config.parsers.etcd import EtcdConfigParser
from eduid_common.session.eduid_session import SessionFactory
from eduid_common.stats import NoOpStats, Statsd
from eduid_userdb import UserDB

DEBUG = os.environ.get('EDUID_APP_DEBUG', False)
if DEBUG:
    stderr.writelines('----- WARNING! EDUID_APP_DEBUG is enabled -----\n')


def eduid_init_app_no_db(name: str, config: dict,
                         config_class: Type[FlaskConfig] = FlaskConfig,
                         app_class: Type[EduIDApp] = AuthnApp) -> EduIDApp:
    """
    Create and prepare the flask app for eduID APIs with all the attributes
    common to all  apps.

     * Parse and merge configurations
     * Add logging
     * Add db connection
     * Add eduID session
    """
    if app_class is Flask:
        app_class = EduIDApp
    app = app_class(name)
    # mypy issue: https://github.com/python/mypy/issues/2427
    app.wsgi_app = ProxyFix(app.wsgi_app)  # type: ignore
    app.request_class = Request
    app.url_map.strict_slashes = False

    try:
        # Load project wide default settings
        cast(Config, app.config).from_object('eduid_webapp.settings.common')
    except ImportError:  # No config found
        pass

    try:
        # Load optional app specific default settings
        cast(Config, app.config).from_object('eduid_webapp.{!s}.settings.common'.format(name))
    except ImportError:  # No app specific default config found
        pass

    # Do not use config from etcd if a config dict is supplied
    if config:
        # Load init time settings
        app.config.update(config)
    else:
        # Init etcd config parsers
        common_parser = EtcdConfigParser('/eduid/webapp/common/')
        app_etcd_namespace = os.environ.get('EDUID_CONFIG_NS', '/eduid/webapp/{!s}/'.format(name))
        app_parser = EtcdConfigParser(app_etcd_namespace)
        # Load optional project wide settings
        app.config.update(common_parser.read_configuration(silent=True))
        # Load optional app specific settings
        app.config.update(app_parser.read_configuration(silent=True))

    # Load optional app specific secrets
    cast(Config, app.config).from_envvar('LOCAL_CFG_FILE', silent=True)

    if not isinstance(app, app_class):
        app.__class__ = app_class

    config = {key.lower(): val for key, val in cast(Config, app.config).items()}
    app.init_config(config_class, config)

    if DEBUG:
        dump_config(app)

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
                   app_class: Type[EduIDApp] = AuthnApp) -> EduIDApp:
    app = eduid_init_app_no_db(name, config=config, config_class=config_class, app_class=app_class)
    app.central_userdb = UserDB(app.config.mongo_uri, 'eduid_am')
    # Set up generic health check views
    from eduid_common.api.views.status import status_views
    app.register_blueprint(status_views)
    return app
