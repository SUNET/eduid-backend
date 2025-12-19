"""
Configuration (file) handling for eduID IdP.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import timedelta
from enum import Enum, StrEnum, unique
from pathlib import Path
from re import Pattern
from typing import IO, Annotated, Any

import importlib_resources
from pydantic import AfterValidator, BaseModel, ConfigDict, Field

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
    mongo_uri: str | None = None


class RedisConfig(BaseModel):
    port: int = 6379
    db: int = 0
    host: str | None = None
    sentinel_hosts: Sequence[str] | None = None
    sentinel_service_name: str | None = None


class CookieConfig(BaseModel):
    key: str
    domain: str | None = None
    path: str = "/"
    secure: bool = True
    httponly: bool = True
    samesite: str | None = None
    max_age_seconds: int | None = None  # None means this is a session cookie


class EduidEnvironment(StrEnum):
    dev = "dev"
    staging = "staging"
    production = "production"


class RootConfig(BaseModel):
    app_name: str
    debug: bool = False
    testing: bool = False
    environment: EduidEnvironment = EduidEnvironment.production
    default_eppn_scope: str = "eduid.se"
    default_language: str = "en"
    model_config = ConfigDict(validate_assignment=True)


class LoggingFilters(StrEnum):
    """Identifiers to coherently map elements in LocalContext.filters to filter classes in logging dictConfig."""

    DEBUG_TRUE = "require_debug_true"
    DEBUG_FALSE = "require_debug_false"
    NAMES = "app_filter"
    SESSION_USER = "user_filter"


class WorkerConfig(RootConfig):
    """
    Configuration common to all celery workers
    """

    audit: bool = False
    celery: CeleryConfig = Field(default_factory=CeleryConfig)
    mongo_uri: str | None = None
    transaction_audit: bool = False


class CORSMixin(BaseModel):
    cors_allow_headers: str | list[str] = "*"
    cors_always_send: bool = True
    cors_automatic_options: bool = True
    cors_expose_headers: str | list[str] | None = None
    cors_intercept_exceptions: bool = True
    cors_max_age: timedelta | int | str | None = None
    cors_methods: str | list[str] = ["GET", "HEAD", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"]
    # The origin(s) to allow requests from. An origin configured here that matches the value of the Origin header in a
    # preflight OPTIONS request is returned as the value of the Access-Control-Allow-Origin response header.
    cors_origins: str | list[str] | Pattern = [r"^eduid\.se$", r".*\.eduid\.se$"]
    # The series of regular expression and (optionally) associated CORS options to be applied to the given resource
    # path.
    # If the value is a dictionary, it’s keys must be regular expressions matching resources, and the values must be
    # another dictionary of configuration options, as described in this section.
    # If the argument is a list, it is expected to be a list of regular expressions matching resources for which the
    # app-wide configured options are applied.
    # If the argument is a string, it is expected to be a regular expression matching resources for which the app-wide
    # configured options are applied.
    cors_resources: dict[str | Pattern, CORSMixin] | list[str | Pattern] | str | Pattern = r"/*"
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
    propagate_exceptions: bool | None = None
    # By default if the application is in debug mode the request context is not
    # popped on exceptions to enable debuggers to introspect the data. This can be
    # disabled by this key. You can also use this setting to force-enable it for non
    # debug execution which might be useful to debug production applications (but
    # also very risky).
    preserve_context_on_exception: bool | None = None
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
    trap_bad_request_errors: bool | None = None
    secret_key: str | None = None
    # the name of the session cookie
    session_cookie_name: str = "sessid"
    # Sets a cookie with legacy SameSite=None, the SameSite key and value is omitted
    cookies_samesite_compat: list = Field(default=[("sessid", "sessid_samesite_compat")])
    # the domain for the session cookie. If this is not set, the cookie will
    # be valid for all subdomains of SERVER_NAME.
    session_cookie_domain: str | None = None
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
    session_cookie_samesite: str | None = None
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
    # the name and port number of the server. Required for subdomain support (e.g.: 'myapp.dev:5000') Note that
    # localhost does not support subdomains so setting this to “localhost” does not help. Setting a SERVER_NAME also by
    # default enables URL generation without a request context but with an application context.
    server_name: str | None = None
    # If the application does not occupy a whole domain or subdomain this can be set to the path where the application
    # is configured to live. This is for session cookie as path value. If domains are used, this should be None.
    application_root: str = "/"
    # The URL scheme that should be used for URL generation if no URL scheme is
    # available. This defaults to http
    preferred_url_scheme: str = "http"
    # If set to a value in bytes, Flask will reject incoming requests with a
    # content length greater than this by returning a 413 status code.
    max_content_length: int | None = None
    templates_auto_reload: bool | None = None
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
    sentry_send_default_pii: bool = False

    def to_mapping(self) -> Mapping[str, Any]:
        return self.model_dump()


class ProfilingConfig(BaseModel):
    """
    Configuration for the profiling using werkzeug.middleware.profiler.ProfilerMiddleware
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)  # allow IO type
    stream: IO | None = None
    sort_by: Iterable[str] = Field(default_factory=lambda: ("time", "calls"))
    restrictions: Iterable[str | int | float] = Field(default_factory=tuple)
    profile_dir: str | None = None
    filename_format: str = "{method}.{path}.{elapsed:.0f}ms.{time:.0f}.prof"


class WebauthnConfigMixin2(BaseModel):
    fido2_rp_id: str  # 'eduid.se'
    fido2_rp_name: str = "eduID Sweden"


class MagicCookieMixin(BaseModel):
    environment: EduidEnvironment = EduidEnvironment.production
    # code to set in a "magic" cookie to bypass various verifications in test environments.
    magic_cookie: str | None = None
    # name of the magic cookie
    magic_cookie_name: str | None = None


class CeleryConfigMixin(BaseModel):
    app_name: str
    celery: CeleryConfig


class LoggingConfigMixin(BaseModel):
    app_name: str
    debug: bool = False
    testing: bool = False
    # If this list contains anything, debug logging will only be performed for these users
    debug_eppns: Sequence[str] = Field(default=[])
    log_format: str = "{asctime} | {levelname:7} | {hostname} | {eppn:11} | {name:35} | {module:10} | {message}"
    log_level: str = "INFO"
    log_filters: Sequence[LoggingFilters] = Field(default=[LoggingFilters.NAMES, LoggingFilters.SESSION_USER])
    logging_config: dict = Field(default={})


class StatsConfigMixin(BaseModel):
    app_name: str
    stats_host: str | None = None
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


class CaptchaConfigMixin(BaseModel):
    captcha_code_length: int = 6
    captcha_width: int = 160
    captcha_height: int = 60
    captcha_fonts: list[Path] = Field(
        default=[
            importlib_resources.files("eduid").joinpath("static/fonts/ProximaNova-Regular.ttf"),
            importlib_resources.files("eduid").joinpath("static/fonts/ProximaNova-Light.ttf"),
            importlib_resources.files("eduid").joinpath("static/fonts/ProximaNova-Bold.ttf"),
        ]
    )
    captcha_font_size: tuple[int, int, int] = (42, 50, 56)
    captcha_max_bad_attempts: int = 100
    captcha_backdoor_code: str = "123456"


class AmConfigMixin(CeleryConfigMixin):
    """Config used by AmRelay"""

    am_relay_for_override: str | None = None  # only set this if f'eduid_{app_name}' is not right


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
    errors_url_template: str | None = None


class Pysaml2SPConfigMixin(BaseModel):
    # Authn algorithms
    authn_sign_alg: str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    authn_digest_alg: str = "http://www.w3.org/2001/04/xmlenc#sha256"

    saml2_settings_module: str
    safe_relay_domain: str = "eduid.se"


@unique
class FrontendAction(Enum):
    ADD_SECURITY_KEY_AUTHN = "addSecurityKeyAuthn"
    CHANGE_PW_AUTHN = "changepwAuthn"
    CHANGE_SECURITY_PREFERENCES_AUTHN = "changeSecurityPreferencesAuthn"
    LOGIN = "login"
    LOGIN_MFA_AUTHN = "loginMfaAuthn"
    REMOVE_IDENTITY = "removeIdentity"
    REMOVE_SECURITY_KEY_AUTHN = "removeSecurityKeyAuthn"
    RESET_PW_MFA_AUTHN = "resetpwMfaAuthn"
    SUPPORT_LOGIN = "supportLogin"
    TERMINATE_ACCOUNT_AUTHN = "terminateAccountAuthn"
    VERIFY_CREDENTIAL = "verifyCredential"
    VERIFY_IDENTITY = "verifyIdentity"


class AuthnParameters(BaseModel):
    force_authn: bool = False  # a new authentication was required
    force_mfa: bool = False  # require MFA even if the user has no token (use Freja or other)
    high_security: bool = False  # opportunistic MFA, request it if the user has a token
    same_user: bool = True  # the same user was required to log in, such as when entering the security center
    max_age: timedelta = timedelta(minutes=5)  # the maximum age of the authentication
    allow_login_auth: bool = False  # allow login authentication as substitute action
    allow_signup_auth: bool = False  # allow during signup
    finish_url: str  # str as we want to use unformatted parts as {app_name} and {authn_id}


class FrontendActionMixin(BaseModel):
    # TODO: maybe we should add a meta action shared by the frontend actions that needs the same level of
    # security so that we could allow an action "of the same level" to be used for another action
    # if the current way means to many logins for the users we can explore it.
    frontend_action_authn_parameters: dict[FrontendAction, AuthnParameters] = Field(
        default={
            FrontendAction.ADD_SECURITY_KEY_AUTHN: AuthnParameters(
                force_authn=True,
                high_security=True,
                allow_login_auth=True,
                allow_signup_auth=True,
                finish_url="https://eduid.se/profile/ext-return/{app_name}/{authn_id}",
            ),
            FrontendAction.CHANGE_PW_AUTHN: AuthnParameters(
                force_authn=True,
                high_security=True,
                allow_login_auth=True,
                finish_url="https://eduid.se/profile/ext-return/{app_name}/{authn_id}",
            ),
            FrontendAction.CHANGE_SECURITY_PREFERENCES_AUTHN: AuthnParameters(
                force_authn=True,
                high_security=True,
                allow_login_auth=True,
                finish_url="https://eduid.se/profile/ext-return/{app_name}/{authn_id}",
            ),
            FrontendAction.LOGIN: AuthnParameters(
                same_user=False,
                finish_url="https://eduid.se/login/ext-return/{app_name}/{authn_id}",
            ),
            FrontendAction.LOGIN_MFA_AUTHN: AuthnParameters(
                force_authn=True,
                allow_login_auth=True,
                finish_url="https://eduid.se/login/ext-return/{app_name}/{authn_id}",
            ),
            FrontendAction.REMOVE_SECURITY_KEY_AUTHN: AuthnParameters(
                force_authn=True,
                force_mfa=True,
                allow_login_auth=True,
                finish_url="https://eduid.se/profile/ext-return/{app_name}/{authn_id}",
            ),
            FrontendAction.RESET_PW_MFA_AUTHN: AuthnParameters(
                force_authn=True,
                allow_login_auth=True,
                finish_url="https://eduid.se/login/ext-return/{app_name}/{authn_id}",
            ),
            FrontendAction.SUPPORT_LOGIN: AuthnParameters(
                force_authn=True, force_mfa=True, allow_login_auth=True, finish_url="https://support.eduid.se/"
            ),
            FrontendAction.VERIFY_IDENTITY: AuthnParameters(
                force_authn=True,
                allow_login_auth=True,
                allow_signup_auth=True,
                finish_url="https://eduid.se/profile/ext-return/{app_name}/{authn_id}",
            ),
            FrontendAction.TERMINATE_ACCOUNT_AUTHN: AuthnParameters(
                force_authn=True,
                high_security=True,
                allow_login_auth=True,
                finish_url="https://eduid.se/profile/ext-return/{app_name}/{authn_id}",
            ),
            FrontendAction.VERIFY_CREDENTIAL: AuthnParameters(
                force_authn=True,
                force_mfa=True,
                allow_login_auth=True,
                allow_signup_auth=True,
                finish_url="https://eduid.se/profile/ext-return/{app_name}/{authn_id}",
            ),
            FrontendAction.REMOVE_IDENTITY: AuthnParameters(
                force_authn=True,
                high_security=True,
                allow_login_auth=True,
                finish_url="https://eduid.se/profile/ext-return/{app_name}/{authn_id}",
            ),
        }
    )
    # slack for recent signup validity as an authn action
    signup_auth_slack: timedelta = timedelta(minutes=3)


class ProofingConfigMixin(FrontendActionMixin):
    # sweden connect
    trust_framework: TrustFramework = TrustFramework.SWECONN
    required_loa: list[str] = Field(default=["loa3"])
    freja_idp: str | None = None

    # eidas
    foreign_trust_framework: TrustFramework = TrustFramework.EIDAS
    foreign_required_loa: list[str] = Field(default=["eidas-nf-sub", "eidas-nf-high"])
    foreign_identity_idp: str | None = None

    # bankid
    bankid_trust_framework: TrustFramework = TrustFramework.BANKID
    bankid_required_loa: list[str] = Field(default=["uncertified-loa3"])
    bankid_idp: str | None = None

    # freja eid
    freja_eid_trust_framework: TrustFramework = TrustFramework.FREJA
    freja_eid_required_loa: list[str] = Field(default=["freja-loa3"])
    freja_eid_required_registration_level: list[str] = Field(default=["PLUS"])
    freja_eid_registration_level_to_loa: dict[str, str | None] = Field(
        default={
            "EXTENDED": None,
            "PLUS": "freja-loa3",
        }
    )

    # identity proofing
    freja_proofing_version: str = Field(default="2023v1")
    foreign_eid_proofing_version: str = Field(default="2022v1")
    svipe_id_proofing_version: str = Field(default="2023v2")
    bankid_proofing_version: str = Field(default="2023v1")
    freja_eid_proofing_version: str = Field(default="2024v1")

    # security key proofing
    security_key_proofing_method: CredentialProofingMethod = Field(default=CredentialProofingMethod.SWAMID_AL3_MFA)
    security_key_proofing_version: str = Field(default="2023v2")
    security_key_foreign_eid_proofing_version: str = Field(default="2022v1")
    security_key_freja_eid_proofing_version: str = Field(default="2024v1")
    security_key_foreign_freja_eid_proofing_version: str = Field(default="2024v1")


class EduIDBaseAppConfig(RootConfig, LoggingConfigMixin, StatsConfigMixin, RedisConfigMixin):
    available_languages: Mapping[str, str] = Field(default={"en": "English", "sv": "Svenska"})
    flask: FlaskConfig = Field(default_factory=FlaskConfig)
    # settings for optional profiling of the application
    profiling: ProfilingConfig | None = None
    mongo_uri: str
    private_userdb_auto_expire: timedelta | None = Field(default=timedelta(days=7))
    # Allow list of URLs that do not need authentication. Unauthenticated requests
    # for these URLs will be served, rather than redirected to the authn service.
    # The list is a list of regex that are matched against the path of the
    # requested URL ex. ^/test$.
    no_authn_urls: list[str] = Field(default=["^/status/healthy$", "^/status/sanity-check$"])
    status_cache_seconds: int = 10


ReasonableDomainName = Annotated[str, Field(min_length=len("x.se")), AfterValidator(lambda v: v.lower())]
DataOwnerName = ReasonableDomainName
ScopeName = ReasonableDomainName


class DataOwnerConfig(BaseModel):
    db_name: str | None = None
    notify: list[str] = []


class AuthnBearerTokenConfig(RootConfig):
    protocol: str = "http"
    server_name: str = "localhost:8000"
    application_root: str = ""
    log_format: str = "{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}"
    no_authn_urls: list[str] = Field(default=["^/status/healthy$", "^/docs/?$", "^/openapi.json"])
    mongo_uri: str = ""
    authorization_mandatory: bool = True
    authorization_token_expire: int = 5 * 60
    keystore_path: Path
    data_owners: dict[DataOwnerName, DataOwnerConfig] = Field(default={})
    max_loaded_data_owner_dbs: int = 10
    # Map scope to data owner name
    scope_mapping: dict[ScopeName, DataOwnerName] = Field(default={})
    # Allow someone with scope x to sudo to scope y
    scope_sudo: dict[ScopeName, set[ScopeName]] = Field(default={})
    requested_access_type: str | None = None
    required_saml_assurance_level: list[str] = Field(default=["http://www.swamid.se/policy/assurance/al3"])
    # group name to match saml entitlement for authorization
    account_manager_default_group: str = "Account Managers"
    account_manager_group_mapping: dict[DataOwnerName, str] = Field(default={})
