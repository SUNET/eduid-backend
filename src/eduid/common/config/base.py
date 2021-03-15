#
# Copyright (c) 2013-2016 NORDUnet A/S
# Copyright (c) 2019 SUNET
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
Configuration (file) handling for eduID IdP.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, List, Mapping, Optional, Sequence, TypeVar

from pydantic import BaseModel, Field


class CeleryConfig(BaseModel):
    """
    Celery configuration
    """

    accept_content: List[str] = Field(default=['application/json'])
    broker_url: str = ''
    result_backend: str = 'cache'
    result_backend_transport_options: dict = Field(default={})
    cache_backend: str = 'memory'
    task_serializer: str = 'json'
    task_eager_propagates: bool = False
    task_always_eager: bool = False
    # backwards incompatible setting that the documentation says will be the default in the future
    broker_transport: str = ''
    broker_transport_options: dict = Field(default={'fanout_prefix': True})
    task_routes: dict = Field(
        default={
            'eduid.workers.am.*': {'queue': 'am'},
            'eduid.workers.msg.*': {'queue': 'msg'},
            'eduid.workers.lookup_mobile.*': {'queue': 'lookup_mobile'},
        }
    )
    mongo_uri: Optional[str] = None


class RedisConfig(BaseModel):
    port: int = 6379
    db: int = 0
    host: Optional[str] = None
    sentinel_hosts: Optional[Sequence[str]] = None
    sentinel_service_name: Optional[str] = None


class CookieConfig(BaseModel):
    key: str
    domain: Optional[str] = None
    path: str = '/'
    secure: bool = True
    httponly: bool = True
    samesite: Optional[str] = None
    max_age_seconds: Optional[int] = None  # None means this is a session cookie


TRootConfigSubclass = TypeVar('TRootConfigSubclass', bound='RootConfig')


class RootConfig(BaseModel):
    app_name: str
    debug: bool = False
    testing: bool = False


# EduIDBaseApp is currently Flask apps
TEduIDBaseAppConfigSubclass = TypeVar('TEduIDBaseAppConfigSubclass', bound='EduIDBaseAppConfig')


class EduidEnvironment(str, Enum):
    dev = 'dev'
    staging = 'staging'
    production = 'production'


class LoggingFilters(str, Enum):
    """ Identifiers to coherently map elements in LocalContext.filters to filter classes in logging dictConfig. """

    DEBUG_TRUE: str = 'require_debug_true'
    DEBUG_FALSE: str = 'require_debug_false'
    NAMES: str = 'app_filter'
    SESSION_USER: str = 'user_filter'


class WorkerConfig(RootConfig):
    """
    Configuration common to all celery workers
    """
    audit: bool = False
    celery: CeleryConfig = Field(default_factory=CeleryConfig)
    environment: EduidEnvironment = EduidEnvironment.production
    mongo_uri: Optional[str] = None
    transaction_audit: bool = False


class FlaskConfig(BaseModel):
    """
    These are configuration keys used by Flask (and flask-babel) itself,
    with the default values provided by flask.
    See the flask documentation for the semantics of each key.
    """

    # What environment the app is running in.
    # This is set by the FLASK_ENV environment variable and may not
    # behave as expected if set in code
    env: str = 'production'
    testing: bool = False
    # explicitly enable or disable the propagation of exceptions.
    # If not set or explicitly set to None this is implicitly true if either
    # TESTING or DEBUG is true.
    propagate_exceptions: Optional[bool] = None
    # By default if the application is in debug mode the request context is not
    # popped on exceptions to enable debuggers to introspect the data. This can be
    # disabled by this key. You can also use this setting to force-enable it for non
    # debug execution which might be useful to debug production applications (but
    # also very risky).
    preserve_context_on_exception: Optional[bool] = None
    # If this is set to True Flask will not execute the error handlers of HTTP
    # exceptions but instead treat the exception like any other and bubble it through
    # the exception stack. This is helpful for hairy debugging situations where you
    # have to find out where an HTTP exception is coming from.
    trap_http_exceptions: bool = False
    # Werkzeug’s internal data structures that deal with request specific data
    # will raise special key errors that are also bad request exceptions. Likewise
    # many operations can implicitly fail with a BadRequest exception for
    # consistency. Since it’s nice for debugging to know why exactly it failed this
    # flag can be used to debug those situations. If this config is set to True you
    # will get a regular traceback instead.
    trap_bad_request_errors: Optional[bool] = None
    secret_key: Optional[str] = None
    # the name of the session cookie
    session_cookie_name: str = 'sessid'
    # Sets a cookie with legacy SameSite=None, the SameSite key and value is omitted
    cookies_samesite_compat: list = Field(default=[('sessid', 'sessid_samesite_compat')])
    # the domain for the session cookie. If this is not set, the cookie will
    # be valid for all subdomains of SERVER_NAME.
    session_cookie_domain: Optional[str] = None
    # the path for the session cookie. If this is not set the cookie will be valid
    # for all of APPLICATION_ROOT or if that is not set for '/'.
    session_cookie_path: str = '/'
    # controls if the cookie should be set with the httponly flag. Defaults to True
    session_cookie_httponly: bool = False
    # controls if the cookie should be set with the secure flag. Defaults to False
    session_cookie_secure: bool = False
    # Restrict how cookies are sent with requests from external sites.
    # Can be set to None (samesite key omitted), 'None', 'Lax' (recommended) or 'Strict'.
    # Defaults to None
    session_cookie_samesite: Optional[str] = None
    # the lifetime of a permanent session as datetime.timedelta object.
    # Starting with Flask 0.8 this can also be an integer representing seconds.
    permanent_session_lifetime: int = 14400  # 4 hours
    session_refresh_each_request: bool = True
    use_x_sendfile: bool = False
    # Default cache control max age to use with send_static_file() (the default
    # static file handler) and send_file(), in seconds. Override this value on a
    # per-file basis using the get_send_file_max_age() hook on Flask or Blueprint,
    # respectively. Defaults to 43200 (12 hours).
    send_file_max_age_default: int = 43200  # 12 hours
    # the name and port number of the server. Required for subdomain support (e.g.: 'myapp.dev:5000') Note that localhost
    # does not support subdomains so setting this to “localhost” does not help. Setting a SERVER_NAME also by default
    # enables URL generation without a request context but with an application context.
    server_name: Optional[str] = None
    # If the application does not occupy a whole domain or subdomain this can be set to the path where the application is
    # configured to live. This is for session cookie as path value. If domains are used, this should be None.
    application_root: str = '/'
    # The URL scheme that should be used for URL generation if no URL scheme is
    # available. This defaults to http
    preferred_url_scheme: str = 'http'
    # If set to a value in bytes, Flask will reject incoming requests with a
    # content length greater than this by returning a 413 status code.
    max_content_length: Optional[int] = None
    # By default Flask serialize object to ascii-encoded JSON. If this is set to
    # False Flask will not encode to ASCII and output strings as-is and return
    # unicode strings. jsonfiy will automatically encode it in utf-8 then for
    # transport for instance.
    json_as_ascii: bool = True
    # By default Flask will serialize JSON objects in a way that the keys are
    # ordered. This is done in order to ensure that independent of the hash seed of
    # the dictionary the return value will be consistent to not trash external HTTP
    # caches. You can override the default behavior by changing this variable. This
    # is not recommended but might give you a performance improvement on the cost of
    # cachability.
    json_sort_keys: bool = True
    # If this is set to True (the default) jsonify responses will be pretty printed
    # if they are not requested by an XMLHttpRequest object (controlled by the
    # X-Requested-With header)
    jsonify_prettyprint_regular: bool = False
    jsonify_mimetype: str = 'application/json'
    templates_auto_reload: Optional[bool] = None
    explain_template_loading: bool = False
    max_cookie_size: int = 4093
    babel_translation_directories: str = 'translations'
    babel_default_locale: str = 'en'
    babel_default_timezone: str = ''
    babel_domain: str = ''
    # the name of the logger
    logger_name: str = ''
    internal_signup_url: str = ''
    # recaptcha_public_key: str = ''
    # recaptcha_private_key: str = ''

    def to_mapping(self) -> Mapping[str, Any]:
        return self.dict()


class WebauthnConfigMixin2(BaseModel):
    fido2_rp_id: str  # 'eduid.se'
    u2f_app_id: str  # 'https://eduid.se/u2f-app-id.json'
    u2f_valid_facets: List[str]  # e.g. ['https://dashboard.dev.eduid.se/', 'https://idp.dev.eduid.se/']


class MagicCookieMixin(BaseModel):
    environment: EduidEnvironment = EduidEnvironment.production
    # code to set in a "magic" cookie to bypass various verifications in test environments.
    magic_cookie: Optional[str] = None
    # name of the magic cookie
    magic_cookie_name: Optional[str] = None


class CeleryConfigMixin(BaseModel):
    app_name: str
    celery: CeleryConfig


class LoggingConfigMixin(BaseModel):
    app_name: str
    testing: bool = False
    debug: bool = False
    # If this list contains anything, debug logging will only be performed for these users
    debug_eppns: Sequence[str] = Field(default=[])
    log_format: str = '{asctime} | {levelname:7} | {hostname} | {eppn:9} | {name:35} | {module:10} | {message}'
    log_level: str = 'INFO'
    log_filters: Sequence[LoggingFilters] = Field(default=[LoggingFilters.NAMES, LoggingFilters.SESSION_USER])
    logging_config: dict = Field(default={})


class StatsConfigMixin(BaseModel):
    app_name: str
    stats_host: Optional[str] = None
    stats_port: int = 8125


class RedisConfigMixin(BaseModel):
    redis_config: RedisConfig = Field(default=RedisConfig())


class VCCSConfigMixin(BaseModel):
    # URL to use with VCCS client. BCP is to have an nginx or similar on
    # localhost that will proxy requests to a currently available backend
    # using TLS.
    vccs_url: str
    # vccs health check credentials
    vccs_check_eppn: str
    vccs_check_password: str


class AmConfigMixin(CeleryConfigMixin):
    """ Config used by AmRelay """

    am_relay_for_override: Optional[str]  # only set this if f'eduid_{app_name}' is not right


class MailConfigMixin(CeleryConfigMixin):
    """ Config used by MailRelay """

    mail_default_from: str = 'no-reply@eduid.se'


class MsgConfigMixin(CeleryConfigMixin):
    """ Config used by MsgRelay """

    eduid_site_name: str = 'eduID'


class EduIDBaseAppConfig(RootConfig, LoggingConfigMixin, StatsConfigMixin, RedisConfigMixin):
    available_languages: Mapping[str, str] = Field(default={'en': 'English', 'sv': 'Svenska'})
    environment: EduidEnvironment = EduidEnvironment.production
    flask: FlaskConfig = Field(default=FlaskConfig())
    mongo_uri: str
    # Allow list of URLs that do not need authentication. Unauthenticated requests
    # for these URLs will be served, rather than redirected to the authn service.
    # The list is a list of regex that are matched against the path of the
    # requested URL ex. ^/test$.
    no_authn_urls: list = Field(default=['^/status/healthy$', '^/status/sanity-check$'])
    status_cache_seconds: int = 10
    # All AuthnBaseApps need this to redirect not-logged-in requests to the authn service
    token_service_url: str
