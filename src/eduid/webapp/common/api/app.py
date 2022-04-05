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
import os
from abc import ABCMeta
from sys import stderr
from typing import Dict, TypeVar

from cookies_samesite_compat import CookiesSameSiteCompatMiddleware
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from eduid.common.config.base import EduIDBaseAppConfig, FlaskConfig
from eduid.common.config.exceptions import BadConfiguration
from eduid.common.logging import init_logging
from eduid.common.stats import init_app_stats
from eduid.userdb.userdb import AmDB
from eduid.webapp.common.api.checks import (
    CheckResult,
    FailCountItem,
    check_am,
    check_lookup_mobile,
    check_mail,
    check_mongo,
    check_msg,
    check_redis,
    check_vccs,
)
from eduid.webapp.common.api.debug import init_app_debug
from eduid.webapp.common.api.exceptions import init_exception_handlers, init_sentry
from eduid.webapp.common.api.middleware import PrefixMiddleware
from eduid.webapp.common.api.request import Request
from eduid.webapp.common.api.utils import init_template_functions
from eduid.webapp.common.authn.utils import no_authn_views
from eduid.webapp.common.session.eduid_session import SessionFactory

DEBUG = os.environ.get('EDUID_APP_DEBUG', False)
if DEBUG:
    stderr.writelines('----- WARNING! EDUID_APP_DEBUG is enabled -----\n')


TFlaskConfigSubclass = TypeVar('TFlaskConfigSubclass', bound=FlaskConfig)


class EduIDBaseApp(Flask, metaclass=ABCMeta):
    """
    Base class for eduID apps, initializing common features and facilities.
    """

    def __init__(
        self, config: EduIDBaseAppConfig, init_central_userdb: bool = True, handle_exceptions: bool = True, **kwargs
    ):
        """
        :param config: EduID Flask app configuration subclass
        :param init_central_userdb: Whether the app requires access to the central user db.
        :param handle_exceptions: Whether to install exception handler or not.
        """
        super().__init__(config.app_name, **kwargs)
        _flask_config = {x.upper(): v for x, v in config.flask.to_mapping().items()}
        self.config.from_mapping(_flask_config)

        # Check for required configuration
        for this in ['SECRET_KEY', 'APPLICATION_ROOT', 'SERVER_NAME']:
            if this not in self.config:
                raise BadConfiguration(f'Flask configuration variable {this} is missing')

        if DEBUG:
            init_app_debug(self)

        # App setup
        self.wsgi_app = ProxyFix(self.wsgi_app)  # type: ignore
        self.request_class = Request
        # autocorrect location header means that redirects defaults to an absolute path
        # werkzeug 2.1.0 changed default value to False
        self.response_class.autocorrect_location_header = True  # type: ignore
        self.url_map.strict_slashes = False

        # Set app url prefix to APPLICATION_ROOT
        self.wsgi_app = PrefixMiddleware(  # type: ignore
            self.wsgi_app, prefix=self.config['APPLICATION_ROOT'], server_name=self.config['SERVER_NAME'],
        )

        # Allow legacy samesite cookie support
        self.wsgi_app = CookiesSameSiteCompatMiddleware(self.wsgi_app, self.config)  # type: ignore

        # Initialize shared features
        init_logging(config)
        if handle_exceptions:
            init_exception_handlers(self)
        init_sentry(self)
        init_template_functions(self)
        self.stats = init_app_stats(config)
        self.session_interface = SessionFactory(config)

        if init_central_userdb:
            self.central_userdb = AmDB(config.mongo_uri)

        # Set up generic health check views
        self.failure_info: Dict[str, FailCountItem] = dict()
        init_status_views(self, config)

    def run_health_checks(
        self,
        mongo: bool = True,
        redis: bool = True,
        am: bool = True,
        msg: bool = True,
        mail: bool = True,
        lookup_mobile: bool = True,
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
        # Lookup Mobile Relay
        elif lookup_mobile and not check_lookup_mobile():
            res.healthy = False
            res.reason = 'lookup_mobile check failed'
            self.logger.warning('lookup_mobile check failed')
        # VCCS
        elif vccs and not check_vccs():
            res.healthy = False
            res.reason = 'vccs check failed'
            self.logger.warning('vccs check failed')
        return res


def init_status_views(app: EduIDBaseApp, config: EduIDBaseAppConfig) -> None:
    """
    Register status views for any app, and configure them as public.
    """
    from eduid.webapp.common.api.views.status import status_views

    app.register_blueprint(status_views)
    # Register status paths for unauthorized requests
    status_paths = ['/status/healthy', '/status/sanity-check']
    no_authn_views(config, status_paths)
    return None
