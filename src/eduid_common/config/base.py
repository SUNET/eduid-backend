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

from dataclasses import dataclass, field
import os
from logging import Logger
from importlib import import_module
from typing import Optional, List, Tuple, Dict, Any, Callable




@dataclass
class CeleryConfig:
    """
    Celery configuration 
    """
    accept_content: List[str] = field(default_factory=lambda: ["application/json"])
    broker_url: str = ''
    result_backend: str = 'cache'
    cache_backend: str = 'memory'
    task_serializer: str = 'json'
    task_eager_propagates: bool = False
    task_always_eager: bool = False
    # backwards incompatible setting that the documentation says will be the default in the future
    broker_transport: str = ''
    broker_transport_options: dict = field(default_factory=lambda: {"fanout_prefix": True})
    task_routes: dict = field(default_factory=lambda: {
      'eduid_am.*': {'queue': 'am'},
      'eduid_msg.*': {'queue': 'msg'},
      'eduid_letter_proofing.*': {'queue': 'letter_proofing'}})
    mongo_uri: Optional[str] = None


@dataclass
class CommonConfig:
    """
    Configuration common to all web apps and celery workers
    """
    devel_mode: bool = False
    # mongo uri
    mongo_uri: Optional[str] = None
    # Celery config -- duplicated for backwards compat
    celery_config: CeleryConfig = field(default_factory=CeleryConfig)
    celery: CeleryConfig = field(default_factory=CeleryConfig)
    audit: bool = False
    transaction_audit: bool = False

    def __post_init__(self):
        # broker_url's default is the empty string, so to check that it is
        # populated with defaults, and so overridable by anything set to the
        # celery key, we check for that.
        if self.celery and (not self.celery_config or
                            not self.celery_config.broker_url):
            self.celery_config = self.celery
        if isinstance(self.celery_config, dict):
            cconfig = {}
            for k, v in self.celery_config.items():
                if k.startswith('CELERY_'):
                    k = k[7:]
                cconfig[k.lower()] = v
            self.celery_config = CeleryConfig(**cconfig)
        self.celery = self.celery_config

    def __getitem__(self, attr: str) -> Any:
        """
        This is needed so that Flask code can access Flask configuration
        """
        try:
            return self.__getattribute__(attr.lower())
        except AttributeError:
            raise KeyError(f'{self} has no {attr} attr')

    def __setitem__(self, attr: str, value: Any):
        setattr(self, attr.lower(), value)

    def get(self, key: str, default: Any = None) -> Any:
        """
        This is needed so that Flask code can access Flask configuration
        """
        try:
            return self.__getattribute__(key.lower())
        except AttributeError:
            return default

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key.lower())

    @classmethod
    def defaults(cls, transform_key: Callable = lambda x: x) -> dict:
        return {transform_key(key): val for key, val in cls.__dict__.items()
                  if isinstance(key, str) and not key.startswith('_') and not callable(val)}

    def to_dict(self, transform_key: Callable = lambda x: x) -> dict:
        return {transform_key(key): val for key, val in self.__dict__.items()
                  if isinstance(key, str) and not key.startswith('_') and not callable(val)}

    def update(self, config: dict, transform_key: Callable = lambda x: x.lower()):
        for key, value in config.items():
            setattr(self, transform_key(key), value)

    def setdefault(self, key: str, value: Any,
                   transform_key: Callable = lambda x: x.lower()):
        tkey = transform_key(key)
        if not getattr(self, tkey):
            setattr(self, tkey, value)
            return value
        return getattr(self, tkey)


@dataclass
class BaseConfig(CommonConfig):
    """
    Configuration common to all web apps, roughly equivalent to the
    "eduid/webapp/common" namespace in etcd - excluding Flask's own
    configuration
    """
    debug: bool = False
    # These below are configuration keys used in the webapps, common to most
    # or at least to several of them.

    # name of the app, which coincides with its namespace in etcd
    app_name: str = ''
    eduid_site_name: str = ''
    eduid_site_url: str = ''
    eduid_static_url: str = ''
    # environment=(dev|staging|pro)
    environment: str = 'dev'
    development: bool = False
    # enable disable debug mode
    logging_config: dict = field(default_factory=dict)
    log_level: str = 'INFO'
    log_file: Optional[str] = None
    log_max_bytes: int = 1000000  # 1 MB
    log_backup_count: int = 10  # 10 x 1 MB
    log_format: str = '%(asctime)s | %(levelname)s | %(hostname)s | %(name)s | %(module)s | %(eppn)s | %(message)s'
    log_type: List[str] = field(default_factory=lambda:['stream'])
    logger : Optional[Logger] = None
    # Redis config
    # The Redis host to use for session storage.
    redis_host: Optional[str] = None
    # The port of the Redis server (integer).
    redis_port: int = 6379
    # The Redis database number (integer).
    redis_db: int = 0
    # Redis sentinel hosts, comma separated
    redis_sentinel_hosts: Optional[List[str]] = None
    # The Redis sentinel 'service name'.
    redis_sentinel_service_name: str = 'redis-cluster'
    saml2_logout_redirect_url: str = 'https://eduid.se/'
    saml2_login_redirect_url: str = ''
    saml2_settings_module: str = ''
    saml2_strip_saml_user_suffix: bool = False
    saml2_user_main_attribute: str = 'eduPersonPrincipalName'
    token_service_url: str = ''
    new_user_date: str = ''
    sms_sender: str = ''
    mail_starttls: bool = False
    template_dir: str = ''
    mail_host: str = ''
    mail_port: str = ''
    am_broker_url: str = ''
    msg_broker_url: str = ''
    teleadress_client_user: str = ''
    teleadress_client_password: str = ''
    available_languages: Dict[str, str] = field(default_factory=lambda: {
        'en': 'English',
        'sv': 'Svenska'
        })
    supported_languages: Dict[str, str] = field(default_factory=lambda: {
        'en': 'English',
        'sv': 'Svenska'
        })
    mail_default_from: str = 'info@eduid.se'
    static_url: str = ''
    dashboard_url: str = ''
    reset_passwd_url: str = ''
    default_finish_url: str = ''
    safe_relay_domain: str = ''
    faq_link: str = ''
    students_link: str = ''
    staff_link: str = ''
    technicians_link: str = ''
    # set absolute URL so it can be included in emails
    signup_url: str = ''
    # URL to use with VCCS client. BCP is to have an nginx or similar on
    # localhost that will proxy requests to a currently available backend
    # using TLS.
    vccs_url: str = ''
    no_authn_urls: list = field(default_factory=lambda: [
        "^/status/healthy$",
        "^/status/sanity-check$"
        ])
    # The plugins for pre-authentication actions that need to be loaded
    action_plugins: list = field(default_factory=lambda: [
        "tou",
        "mfa"
        ])
    # The current version of the terms of use agreement.
    tou_version: str = '2017-v6'
    current_tou_version: str = '2017-v6'  # backwards compat
    fido2_rp_id: str = ''
    stats_host: str = ''
    stats_port: int = 0

    @classmethod
    def init_config(cls, superns: str = 'webapp',
                    test_config: Optional[dict] = None, debug: bool = True) -> BaseConfig:
        """
        Initialize configuration with values from etcd (or with test values)
        XXX remove when the IdP no lnger uses it
        """
        config : Dict[str, Any] = {
                'debug': debug,
                }
        if test_config:
            # Load init time settings
            test_config = {k.lower(): v for k, v in test_config.items()}
            config.update(test_config)
        else:
            from eduid_common.config.parsers.etcd import EtcdConfigParser

            common_namespace = os.environ.get('EDUID_CONFIG_COMMON_NS', f'/eduid/{superns}/common/')
            common_parser = EtcdConfigParser(common_namespace)
            common_config = common_parser.read_configuration(silent=True)
            common_config = {k.lower(): v for k, v in common_config.items()}
            config.update(common_config)

            namespace = os.environ.get('EDUID_CONFIG_NS', f'/eduid/{superns}/{cls.app_name}/')
            parser = EtcdConfigParser(namespace)
            # Load optional app specific settings
            proper_config = parser.read_configuration(silent=True)
            proper_config = {k.lower(): v for k, v in proper_config.items()}
            config.update(proper_config)

        return cls(**config)


@dataclass
class FlaskConfig(BaseConfig):
    """
    These are configuration keys used by Flask (and flask-babel) itself,
    with the default values provided by flask.
    See the flask documentation for the semantics of each key.
    """
    # What environment the app is running in.
    # This is set by the FLASK_ENV environment variable and may not
    # behave as expected if set in code
    env : str = 'production'
    testing: bool = False
    propagate_exceptions: Optional[bool] = None
    preserve_context_on_exception: Optional[bool] = None
    trap_http_exceptions: bool = False
    trap_bad_request_errors: Optional[bool] = None
    secret_key: Optional[str] = None
    # session cookie
    session_cookie_name: str = 'sessid'
    # the domain for the session cookie. If this is not set, the cookie will
    # be valid for all subdomains of SERVER_NAME.
    session_cookie_domain: Optional[str] = None
    session_cookie_path: Optional[str] = None
    session_cookie_httponly: bool = True
    session_cookie_secure: bool = False
    session_cookie_samesite: Optional[str] = None
    permanent_session_lifetime: int = 2678400  # 31 days
    session_refresh_each_request: bool = True
    use_x_sendfile: bool = False
    send_file_max_age_default: int = 43200  # 12 hours
    server_name: Optional[str] = None
    application_root: str = '/'
    # The URL scheme that should be used for URL generation if no URL scheme is
    # available. This defaults to http
    preferred_url_scheme: str = 'http'
    max_content_length: Optional[int] = None
    json_as_ascii: bool = True
    json_sort_keys: bool = True
    jsonify_prettyprint_regular: bool = False
    jsonify_mimetype: str = 'application/json'
    templates_auto_reload: Optional[bool] = None
    explain_template_loading: bool = False
    max_cookie_size: int = 4093
    babel_translation_directories: List[str] = field(default_factory=list)
    babel_default_locale: str = 'en'
    babel_default_timezone: str = ''
    babel_domain: str = ''
    logger_name: str = ''

    # XXX attributes that belong in the config classes for the particular apps,
    # to be removed when eduid-webapp starts using the new config classes
    u2f_app_id: str = ''
    password_length: int = 8
    phone_verification_timeout: int = 5
    webauthn_max_allowed_tokens: int = 5
    bundle_path: str = ''
    dashboard_bundle_path: str = ''
    dashboard_bundle_version: str = ''
    signup_bundle_path: str = ''
    signup_bundle_version: str = ''
    bundles_path: str = ''
    bundle_version: str = ''
    bundles_version: str = ''
    support_personnel: str = ''
    signup_authn_url: str = ''
    email_code_timeout: int = 0
    password_entropy: int = 0
    default_country_code: str = 'en'
    provider_configuration_info: str = ''
    ekopost_api_uri: str = ''
    email_verify_redirect_url: str = ''
    token_verify_redirect_url: str = ''
    signup_authn_success_redirect_url: str = ''
    tou_url: str = ''
    u2f_max_allowed_tokens: int = 0
    phone_code_timeout: int = 0
    chpass_timeout: int = 0
    throttle_resend_seconds: int = 0
    client_registration_info: str = ''
    lookup_mobile_broker_url: str = ''
    ekopost_api_user: str = ''
    ekopost_api_verify_ssl: bool = False
    ekopost_debug_pdf: bool = False
    email_verification_timeout: int = 0
    nin_verify_redirect_url: str = ''
    signup_authn_failure_redirect_url: str = ''
    idp_url: str = ''
    recaptcha_public_key: str = ''
    u2f_facets: str = ''
    userinfo_endpoint_method: str = ''
    letter_wait_time_hours: int = 0
    ekopost_api_pw: str = ''
    action_url: str = ''
    internal_signup_url: str = ''
    recaptcha_private_key: str = ''
    freja_jws_algorithm: str = ''
    freja_expire_time_hours: int = 0
    seleg_expire_time_hours: int = 0
    freja_iarp: str = ''
    freja_response_protocol: str = ''
    authentication_context_map: str = ''
    mfa_testing: bool = False
    freja_jws_key_id: str = ''
    authn_sign_alg: str = ''
    u2f_valid_facets: list = field(default_factory=list)
    u2f_max_description_length: int = 0
    freja_jwk_secret: str = ''
    orcid_verify_redirect_url: str = ''
    unsolicited_response_redirect_url: str = ''
    mfa_authn_idp: str = ''
    eidas_url: str = ''
    authn_digest_alg: str = ''
    staging_nin_map: dict = field(default_factory=dict)
    generate_u2f_challenges: bool = False
    mail_username: str = ''
    mongo_password: str = ''
