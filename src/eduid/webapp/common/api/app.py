"""
Define a EduIDApp to create a Flask app and update
it with all attributes common to all eduID services.
"""

from __future__ import annotations

import os
from abc import ABCMeta
from sys import stderr
from typing import TYPE_CHECKING, Any, TypeVar

from cookies_samesite_compat import CookiesSameSiteCompatMiddleware
from flask import Flask
from flask_cors import CORS
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
    check_mongo,
    check_msg,
    check_redis,
    check_vccs,
)
from eduid.webapp.common.api.debug import init_app_debug
from eduid.webapp.common.api.exceptions import init_exception_handlers, init_sentry
from eduid.webapp.common.api.middleware import PrefixMiddleware
from eduid.webapp.common.authn.utils import no_authn_views
from eduid.webapp.common.session.eduid_session import SessionFactory

if TYPE_CHECKING:
    from _typeshed.wsgi import WSGIApplication
    from werkzeug.middleware.profiler import ProfilerMiddleware

DEBUG = os.environ.get("EDUID_APP_DEBUG", "False").lower() != "false"
if DEBUG:
    stderr.writelines("----- WARNING! EDUID_APP_DEBUG is enabled -----\n")


class EduIDBaseApp(Flask, metaclass=ABCMeta):
    """
    Base class for eduID apps, initializing common features and facilities.
    """

    def __init__(
        self,
        config: EduIDBaseAppConfig,
        init_central_userdb: bool = True,
        handle_exceptions: bool = True,
        **kwargs: Any,
    ) -> None:
        """
        :param config: EduID Flask app configuration subclass
        :param init_central_userdb: Whether the app requires access to the central user db.
        :param handle_exceptions: Whether to install exception handler or not.
        """
        super().__init__(config.app_name, **kwargs)
        _flask_config = {x.upper(): v for x, v in config.flask.to_mapping().items()}
        self.config.from_mapping(_flask_config)

        # Check for required configuration
        for this in ["SECRET_KEY", "APPLICATION_ROOT", "SERVER_NAME"]:
            if this not in self.config:
                raise BadConfiguration(f"Flask configuration variable {this} is missing")

        if DEBUG:
            init_app_debug(self)

        # App setup
        self.wsgi_app = ProxyFix(self.wsgi_app)  # type: ignore[method-assign]
        # autocorrect location header means that redirects defaults to an absolute path
        # werkzeug 2.1.0 changed default value to False
        self.response_class.autocorrect_location_header = True
        self.url_map.strict_slashes = False

        # Set app url prefix to APPLICATION_ROOT
        self.wsgi_app = PrefixMiddleware(  # type: ignore[method-assign]
            self.wsgi_app,
            prefix=config.flask.application_root,
            server_name=config.flask.server_name or "",
        )

        # Allow legacy samesite cookie support
        self.wsgi_app = CookiesSameSiteCompatMiddleware(self.wsgi_app, self.config)  # type: ignore[method-assign]

        # Initialize shared features
        init_logging(config)
        if handle_exceptions:
            init_exception_handlers(self)
        init_sentry(self)
        CORS(self)
        self.stats = init_app_stats(config)
        self.session_interface = SessionFactory(config)

        self._central_userdb: AmDB | None = None
        if init_central_userdb:
            self._central_userdb = AmDB(config.mongo_uri)

        # Set up generic health check views
        self.failure_info: dict[str, FailCountItem] = dict()
        init_status_views(self, config)

        # Profiling setup
        if config.profiling is not None:
            self.config["PROFILE"] = True
            self.wsgi_app = init_app_profiling(self.wsgi_app, config)  # type: ignore[method-assign]
            self.logger.warning("Profiling enabled")
            self.logger.debug(f"Profiler settings: {config.profiling}")

    @property
    def central_userdb(self) -> AmDB:
        if not isinstance(self._central_userdb, AmDB):
            raise RuntimeError("Central userdb not initialised")
        return self._central_userdb

    def run_health_checks(
        self,
        mongo: bool = True,
        redis: bool = True,
        am: bool = True,
        msg: bool = True,
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
            res.reason = "mongodb check failed"
            self.logger.warning("mongodb check failed")
        # Redis
        elif redis and not check_redis():
            res.healthy = False
            res.reason = "redis check failed"
            self.logger.warning("redis check failed")
        # AM
        elif am and not check_am():
            res.healthy = False
            res.reason = "am check failed"
            self.logger.warning("am check failed")
        # MSG
        elif msg and not check_msg():
            res.healthy = False
            res.reason = "msg check failed"
            self.logger.warning("msg check failed")
        # Lookup Mobile Relay
        elif lookup_mobile and not check_lookup_mobile():
            res.healthy = False
            res.reason = "lookup_mobile check failed"
            self.logger.warning("lookup_mobile check failed")
        # VCCS
        elif vccs and not check_vccs():
            res.healthy = False
            res.reason = "vccs check failed"
            self.logger.warning("vccs check failed")
        return res


def init_status_views(app: EduIDBaseApp, config: EduIDBaseAppConfig) -> None:
    """
    Register status views for any app, and configure them as public.
    """
    from eduid.webapp.common.api.views.status import status_views

    app.register_blueprint(status_views)
    # Register status paths for unauthorized requests
    status_paths = ["/status/healthy", "/status/sanity-check"]
    no_authn_views(config, status_paths)


def init_app_profiling(app: WSGIApplication, config: EduIDBaseAppConfig) -> ProfilerMiddleware:
    """
    Setup profiling middleware for any app.
    """
    import sys

    from werkzeug.middleware.profiler import ProfilerMiddleware

    if config.profiling is None:
        raise BadConfiguration("No profiling configuration found")

    # handle stream default here to avoid unnecessary import in config
    if config.profiling.stream is None:
        config.profiling.stream = sys.stdout

    app = ProfilerMiddleware(
        app,
        stream=config.profiling.stream,
        sort_by=config.profiling.sort_by,
        restrictions=config.profiling.restrictions,
        profile_dir=config.profiling.profile_dir,
        filename_format=config.profiling.filename_format,
    )
    return app
