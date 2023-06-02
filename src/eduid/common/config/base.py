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

from datetime import timedelta
from enum import Enum
from re import Pattern
from typing import Any, Mapping, Optional, Sequence, TypeVar, Union

from pydantic import BaseModel, Field

from eduid.userdb.credentials import CredentialProofingMethod
from eduid.userdb.credentials.external import TrustFramework


class CeleryConfig(BaseModel):
    """
    Celery configuration
    """

    accept_content: list[str] = Field(default=["application/json"])
    broker_url: str = ""
    result_backend: str = "cache"
    result_backend_transport_options: dict = Field(default={})
    cache_backend: str = "memory"
    task_serializer: str = "json"
    task_eager_propagates: bool = False
    task_always_eager: bool = False
    # backwards incompatible setting that the documentation says will be the default in the future
    broker_transport: str = ""
    broker_transport_options: dict = Field(default={"fanout_prefix": True})
    task_routes: dict = Field(
        default={
            "eduid.workers.am.*": {"queue": "am"},
            "eduid.workers.msg.*": {"queue": "msg"},
            "eduid.workers.lookup_mobile.*": {"queue": "lookup_mobile"},
            # Old task names, still in use
            "eduid_am.tasks.*": {"queue": "am"},
            "eduid_msg.tasks.*": {"queue": "msg"},
            "eduid_lookup_mobile.tasks.*": {"queue": "lookup_mobile"},
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
    path: str = "/"
    secure: bool = True
    httponly: bool = True
    samesite: Optional[str] = None
    max_age_seconds: Optional[int] = None  # None means this is a session cookie


TRootConfigSubclass = TypeVar("TRootConfigSubclass", bound="RootConfig")


class RootConfig(BaseModel):
    app_name: str
    debug: bool = False
    testing: bool = False

    class Config:
        validate_assignment = True  # validate data when test cases modify the config object


# EduIDBaseApp is currently Flask apps
TEduIDBaseAppConfigSubclass = TypeVar("TEduIDBaseAppConfigSubclass", bound="EduIDBaseAppConfig")


class EduidEnvironment(str, Enum):
    dev = "dev"
    staging = "staging"
    production = "production"


class LoggingFilters(str, Enum):
    """Identifiers to coherently map elements in LocalContext.filters to filter classes in logging dictConfig."""

    DEBUG_TRUE: str = "require_debug_true"
    DEBUG_FALSE: str = "require_debug_false"
    NAMES: str = "app_filter"
    SESSION_USER: str = "user_filter"


class WorkerConfig(RootConfig):
    """
    Configuration common to all celery workers
    """

    audit: bool = False
    celery: CeleryConfig = Field(default_factory=CeleryConfig)
    environment: EduidEnvironment = EduidEnvironment.production
    mongo_uri: Optional[str] = None
    transaction_audit: bool = False


class CORSMixin(BaseModel):
    cors_allow_headers: Union[str, list[str]] = "*"
    cors_always_send: bool = True
    cors_automatic_options: bool = True
    cors_expose_headers: Optional[Union[str, list[str]]] = None
    cors_intercept_exceptions: bool = True
    cors_max_age: Optional[Union[timedelta, int, str]] = None
    cors_methods: Union[str, list[str]] = ["GET", "HEAD", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"]
    # The origin(s) to allow requests from. An origin configured here that matches the value of the Origin header in a
    # preflight OPTIONS request is returned as the value of the Access-Control-Allow-Origin response header.
    cors_origins: Union[str, list[str], Pattern] = [r"^eduid\.se$", r".*\.eduid\.se$"]
    # The series of regular expression and (optionally) associated CORS options to be applied to the given resource
    # path.
    # If the value is a dictionary, it’s keys must be regular expressions matching resources, and the values must be
    # another dictionary of configuration options, as described in this section.
    # If the argument is a list, it is expected to be a list of regular expressions matching resources for which the
    # app-wide configured options are applied.
    # If the argument is a string, it is expected to be a regular expression matching resources for which the app-wide
    # configured options are applied.
    cors_resources: Union[dict[Union[str, Pattern], CORSMixin], list[Union[str, Pattern]], Union[str, Pattern]] = r"/*"
    cors_send_wildcard: bool = False
    cors_supports_credentials: bool = True
    cors_vary_header: bool = True


class FlaskConfig(CORSMixin):
    """
    These are configuration keys used by Flask (and flask plugins) itself,
    with the default values provided by flask.
    See the flask documentation for the semantics of each key.
    """

    # What environment the app is running in.
    # This is set by the FLASK_ENV environment variable and may not
    # behave as expected if set in code
    env: str = "production"
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
    session_cookie_name: str = "sessid"
    # Sets a cookie with legacy SameSite=None, the SameSite key and value is omitted
    cookies_samesite_compat: list = Field(default=[("sessid", "sessid_samesite_compat")])
    # the domain for the session cookie. If this is not set, the cookie will
    # be valid for all subdomains of SERVER_NAME.
    session_cookie_domain: Optional[str] = None
    # the path for the session cookie. If this is not set the cookie will be valid
    # for all of APPLICATION_ROOT or if that is not set for '/'.
    session_cookie_path: str = "/"
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
    application_root: str = "/"
    # The URL scheme that should be used for URL generation if no URL scheme is
    # available. This defaults to http
    preferred_url_scheme: str = "http"
    # If set to a value in bytes, Flask will reject incoming requests with a
    # content length greater than this by returning a 413 status code.
    max_content_length: Optional[int] = None
    templates_auto_reload: Optional[bool] = None
    explain_template_loading: bool = False
    max_cookie_size: int = 4093
    babel_translation_directories: list[str] = ["translations"]
    babel_default_locale: str = "en"
    babel_default_timezone: str = ""
    babel_domain: str = ""
    # the name of the logger
    logger_name: str = ""
    internal_signup_url: str = ""
    sentry_dsn: str = ""

    def to_mapping(self) -> Mapping[str, Any]:
        return self.dict()


class WebauthnConfigMixin2(BaseModel):
    fido2_rp_id: str  # 'eduid.se'
    fido2_rp_name: str = "eduID Sweden"


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
    log_format: str = "{asctime} | {levelname:7} | {hostname} | {eppn:11} | {name:35} | {module:10} | {message}"
    log_level: str = "INFO"
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
    """Config used by AmRelay"""

    am_relay_for_override: Optional[str]  # only set this if f'eduid_{app_name}' is not right


class MailConfigMixin(CeleryConfigMixin):
    """Config used by MailRelay"""

    eduid_site_name: str = "eduID"
    eduid_site_url: str = "https://eduid.se"

    mail_default_from: str = "no-reply@eduid.se"


class MsgConfigMixin(CeleryConfigMixin):
    """Config used by MsgRelay"""

    eduid_site_name: str = "eduID"


class TouConfigMixin(BaseModel):
    tou_version: str = "2016-v1"


class PasswordConfigMixin(BaseModel):
    password_length: int = 12
    password_entropy: int = 25  # KANTARA
    min_zxcvbn_score: int = 3  # SWAMID


class ErrorsConfigMixin(BaseModel):
    errors_url_template: Optional[str] = None


class Pysaml2SPConfigMixin(BaseModel):
    frontend_action_finish_url: dict[str, str] = Field(default={})

    # Authn algorithms
    authn_sign_alg: str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    authn_digest_alg: str = "http://www.w3.org/2001/04/xmlenc#sha256"

    saml2_settings_module: str
    safe_relay_domain: str = "eduid.se"


class ProofingConfigMixin(BaseModel):
    # sweden connect
    trust_framework: TrustFramework = TrustFramework.SWECONN
    required_loa: list[str] = Field(default=["loa3"])  # one of authentication_context_map below
    freja_idp: Optional[str] = None

    # eidas
    foreign_trust_framework: TrustFramework = TrustFramework.EIDAS
    foreign_required_loa: list[str] = Field(
        default=["eidas-nf-low", "eidas-nf-sub", "eidas-nf-high"]
    )  # one of authentication_context_map below
    foreign_identity_idp: Optional[str] = None

    # identity proofing
    freja_proofing_version: str = Field(default="2018v1")
    foreign_eid_proofing_version: str = Field(default="2022v1")
    svipe_id_proofing_version: str = Field(default="2023v1")

    # security key proofing
    security_key_proofing_method: CredentialProofingMethod = Field(default=CredentialProofingMethod.SWAMID_AL3_MFA)
    security_key_proofing_version: str = Field(default="2018v1")
    security_key_foreign_eid_proofing_version: str = Field(default="2022v1")

    frontend_action_finish_url: dict[str, str] = Field(default={})
    fallback_redirect_url: str = "https://dashboard.eduid.se"


class EduIDBaseAppConfig(RootConfig, LoggingConfigMixin, StatsConfigMixin, RedisConfigMixin):
    available_languages: Mapping[str, str] = Field(default={"en": "English", "sv": "Svenska"})
    environment: EduidEnvironment = EduidEnvironment.production
    flask: FlaskConfig = Field(default_factory=FlaskConfig)
    mongo_uri: str
    # Allow list of URLs that do not need authentication. Unauthenticated requests
    # for these URLs will be served, rather than redirected to the authn service.
    # The list is a list of regex that are matched against the path of the
    # requested URL ex. ^/test$.
    no_authn_urls: list[str] = Field(default=["^/status/healthy$", "^/status/sanity-check$"])
    # Feature opt-in for new-style authn responses, requires new frontend code.
    enable_authn_json_response: bool = False
    status_cache_seconds: int = 10
    # All AuthnBaseApps need this to redirect not-logged-in requests to the authn service
    token_service_url: str
