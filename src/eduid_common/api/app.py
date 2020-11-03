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
from abc import ABCMeta
from sys import stderr
from typing import Dict, Optional, TypeVar

from cookies_samesite_compat import CookiesSameSiteCompatMiddleware
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from eduid_userdb import UserDB

from eduid_common.api.checks import (
    CheckResult,
    FailCountItem,
    check_am,
    check_mail,
    check_mongo,
    check_msg,
    check_redis,
    check_vccs,
)
from eduid_common.api.debug import init_app_debug
from eduid_common.api.exceptions import init_exception_handlers, init_sentry
from eduid_common.api.logging import init_logging
from eduid_common.api.middleware import PrefixMiddleware
from eduid_common.api.request import Request
from eduid_common.api.utils import init_template_functions
from eduid_common.authn.utils import no_authn_views
from eduid_common.config.base import FlaskConfig
from eduid_common.config.exceptions import BadConfiguration
from eduid_common.config.parsers.etcd import EtcdConfigParser
from eduid_common.session.eduid_session import SessionFactory
from eduid_common.stats import init_app_stats

DEBUG = os.environ.get('EDUID_APP_DEBUG', False)
if DEBUG:
    stderr.writelines('----- WARNING! EDUID_APP_DEBUG is enabled -----\n')


TFlaskConfigSubclass = TypeVar('TFlaskConfigSubclass', bound='FlaskConfig')


class EduIDBaseApp(Flask, metaclass=ABCMeta):
    """
    Base class for eduID apps, initializing common features and facilities.
    """

    def __init__(self, name: str, init_central_userdb: bool = True, handle_exceptions: bool = True, **kwargs):
        """
        :param name: name of the app
        :param config_class: the dataclass with configuration settings
        :param config: a dict with configuration settings, used in tests to
                       override defaults.
        :param init_central_userdb: whether the app requires access to the
                                    central user db.
        """
        if not isinstance(self.config, FlaskConfig):
            raise TypeError('self.config is not a (subclass of) FlaskConfig')

        _saved_config = self.config
        super().__init__(name, **kwargs)
        self.config: FlaskConfig = _saved_config  # type: ignore

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
        self.wsgi_app = PrefixMiddleware(  # type: ignore
            self.wsgi_app, prefix=self.config.application_root, server_name=self.config.server_name,
        )

        # Allow legacy samesite cookie support
        self.wsgi_app = CookiesSameSiteCompatMiddleware(self.wsgi_app, self.config)  # type: ignore

        # Initialize shared features
        init_logging(self)
        if handle_exceptions:
            init_exception_handlers(self)
        init_sentry(self)
        init_template_functions(self)
        self.stats = init_app_stats(self)
        self.session_interface = SessionFactory(self.config)
        self.failure_info: Dict[str, FailCountItem] = dict()

        if init_central_userdb:
            self.central_userdb = UserDB(self.config.mongo_uri, 'eduid_am')

        # Set up generic health check views
        init_status_views(self)

    def run_health_checks(
        self,
        mongo: bool = True,
        redis: bool = True,
        am: bool = True,
        msg: bool = True,
        mail: bool = True,
        vccs: bool = True,
    ) -> CheckResult:
        """
        Used in status health check view to run the apps checks
        """
        res = CheckResult(healthy=True)
        # MongoDB
        if mongo and not check_mongo():
            res.healthy = False
            res.reason = 'mongodb check failed'
            self.logger.warning('mongodb check failed')
        # Redis
        elif redis and not check_redis():
            res.healthy = False
            res.reason = 'redis check failed'
            self.logger.warning('redis check failed')
        # AM
        elif am and not check_am():
            res.healthy = False
            res.reason = 'am check failed'
            self.logger.warning('am check failed')
        # MSG
        elif msg and not check_msg():
            res.healthy = False
            res.reason = 'msg check failed'
            self.logger.warning('msg check failed')
        # Mail Relay
        elif mail and not check_mail():
            res.healthy = False
            res.reason = 'mail check failed'
            self.logger.warning('mail check failed')
        # VCCS
        elif vccs and not check_vccs():
            res.healthy = False
            res.reason = 'vccs check failed'
            self.logger.warning('vccs check failed')
        return res


def get_app_config(name: str, config: Optional[dict] = None) -> dict:
    """
    Get configuration for flask app.

    If config is not provided, retrieve configuration values from etcd.
    If there is an env var LOCAL_CFG_FILE pointing to a file with configuration
    keys, load them as well.
    """
    warnings.warn(
        "This function will be removed in a future version of eduid_common. Use 'BaseConfig.init_config()' instead.",
        DeprecationWarning,
        stacklevel=2,
    )
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


def init_status_views(app: EduIDBaseApp) -> EduIDBaseApp:
    """
    Register status views for any app, and configure them as public.
    """
    from eduid_common.api.views.status import status_views

    app.register_blueprint(status_views)
    # Register status paths for unauthorized requests
    status_paths = ['/status/healthy', '/status/sanity-check']
    app = no_authn_views(app, status_paths)
    return app
