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

from werkzeug.contrib.fixers import ProxyFix

from eduid_userdb import UserDB
from eduid_common.authn.middleware import AuthnApp
from eduid_common.authn.utils import no_authn_views
from eduid_common.api.request import Request
from eduid_common.api.session import SessionFactory
from eduid_common.api.logging import init_logging
from eduid_common.api.utils import init_template_functions
from eduid_common.api.exceptions import init_exception_handlers, init_sentry
from eduid_common.api.middleware import PrefixMiddleware
from eduid_common.config.parsers.etcd import EtcdConfigParser
from eduid_common.stats import NoOpStats, Statsd


def eduid_init_app_no_db(name, config, app_class=AuthnApp):
    """
    Create and prepare the flask app for eduID APIs with all the attributes
    common to all  apps.

     * Parse and merge configurations
     * Add logging
     * Add db connection
     * Add eduID session

    :param name: The name of the instance, it will affect the configuration file
                 loaded from the filesystem.
    :type name: str
    :param config: any additional configuration settings. Specially useful
                   in test cases
    :type config: dict
    :param app_class: The class used to build the flask app. Should be a
                      descendant of flask.Flask
    :type app_class: type

    :return: the flask application.
    :rtype: flask.Flask
    """
    app = app_class(name)
    app.wsgi_app = ProxyFix(app.wsgi_app)
    app.request_class = Request
    app.url_map.strict_slashes = False

    # Init etcd config parsers
    common_parser = EtcdConfigParser('/eduid/webapp/common/')
    app_parser = EtcdConfigParser('/eduid/webapp/{!s}/'.format(name))

    # Load project wide default settings
    app.config.from_object('eduid_webapp.settings.common')

    try:
        # Load optional app specific default settings
        app.config.from_object('eduid_webapp.{!s}.settings.common'.format(name))
    except ImportError:  # No app specific default config found
        pass

    # Load optional project wide settings
    app.config.update(common_parser.read_configuration(silent=True))
    # Load optional app specific settings
    app.config.update(app_parser.read_configuration(silent=True))

    # Load optional app specific secrets
    app.config.from_envvar('LOCAL_CFG_FILE', silent=True)

    # Load optional init time settings
    app.config.update(config)

    # Set app url prefix to APPLICATION_ROOT
    app.wsgi_app = PrefixMiddleware(app.wsgi_app, prefix=app.config['APPLICATION_ROOT'],
                                    server_name=app.config['SERVER_NAME'])

    # Initialize shared features
    app = init_logging(app)
    app = init_exception_handlers(app)
    app = init_sentry(app)
    app = init_template_functions(app)
    app.session_interface = SessionFactory(app.config)

    stats_host = app.config.get('STATS_HOST', False)
    if not stats_host:
        app.stats = NoOpStats()
    else:
        stats_port = app.config.get('STATS_PORT', 8125)
        app.stats = Statsd(host=stats_host, port=stats_port, prefix=name)

    return app


def eduid_init_app(name, config, app_class=AuthnApp):
    app = eduid_init_app_no_db(name, config, app_class=app_class)
    app.central_userdb = UserDB(app.config['MONGO_URI'], 'eduid_am')  # XXX: Needs updating when we change db
    # Set up generic health check views
    from eduid_common.api.views.status import status_views
    app.register_blueprint(status_views)
    # Register view path that should not be authorized
    app = no_authn_views(app, ['/status/healthy', '/status/sanity-check'])
    return app
