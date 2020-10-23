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

import importlib.machinery
import importlib.util
import logging
import os
import pprint
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Mapping, Optional, Sequence, Type, TypeVar

import yaml

logger = logging.getLogger(__name__)


@dataclass
class CeleryConfig:
    """
    Celery configuration
    """

    accept_content: List[str] = field(default_factory=lambda: ["application/json"])
    broker_url: str = ''
    result_backend: str = 'cache'
    result_backend_transport_options: dict = field(default_factory=dict)
    cache_backend: str = 'memory'
    task_serializer: str = 'json'
    task_eager_propagates: bool = False
    task_always_eager: bool = False
    # backwards incompatible setting that the documentation says will be the default in the future
    broker_transport: str = ''
    broker_transport_options: dict = field(default_factory=lambda: {"fanout_prefix": True})
    task_routes: dict = field(
        default_factory=lambda: {
            'eduid_am.*': {'queue': 'am'},
            'eduid_msg.*': {'queue': 'msg'},
            'eduid_letter_proofing.*': {'queue': 'letter_proofing'},
        }
    )
    mongo_uri: Optional[str] = None


@dataclass(frozen=True)
class RedisConfig(object):
    port: int = 6379
    db: int = 0
    host: Optional[str] = None
    sentinel_hosts: Optional[Sequence[str]] = None
    sentinel_service_name: Optional[str] = None


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
    validation_url: str = ''

    @classmethod
    def filter_config(cls, config: Mapping) -> Mapping:
        # Only try to load the key, value pairs that config class cls expects
        field_names = set(f.name for f in fields(cls))
        filtered_config = {k: v for k, v in config.items() if k in field_names}
        return filtered_config

    def __post_init__(self):
        """
        Set celery configuration as a typed dataclass
        """
        for conf in (self.celery, self.celery_config):
            if isinstance(conf, dict):
                self.celery_config = CeleryConfig(**conf)
                break
        self.celery = self.celery_config

    def __getitem__(self, attr: str) -> Any:
        """
        This is a dict method, used on the configuration dicts by either
        flask or celery
        """
        try:
            return self.__getattribute__(attr.lower())
        except AttributeError:
            raise KeyError(f'{self} has no {attr} attr')

    def __setitem__(self, attr: str, value: Any):
        """
        This is a dict method, used on the configuration dicts by either
        flask or celery
        """
        setattr(self, attr.lower(), value)

    def get(self, key: str, default: Any = None) -> Any:
        """
        This is a dict method, used on the configuration dicts by either
        flask or celery
        """
        try:
            return self.__getattribute__(key.lower())
        except AttributeError:
            return default

    def __contains__(self, key: str) -> bool:
        """
        This is a dict method, used on the configuration dicts by either
        flask or celery
        """
        return hasattr(self, key.lower())

    def update(self, config: dict):
        """
        This is a dict method, used on the configuration dicts by either
        flask or celery
        """
        for key, value in config.items():
            setattr(self, key, value)

    def setdefault(self, key: str, value: Any):
        """
        This is a dict method, used on the configuration dicts by either
        flask or celery
        """
        key = key.lower()
        if not getattr(self, key):
            setattr(self, key, value)
            return value
        return getattr(self, key)

    @classmethod
    def defaults(cls) -> dict:
        """
        get a dict with the default values for all configuration keys
        """
        return {
            key: val
            for key, val in cls.__dict__.items()
            if isinstance(key, str) and not key.startswith('_') and not callable(val)
        }

    def to_dict(self) -> dict:
        """
        get a dict with all configured values
        """
        return {
            key: val
            for key, val in self.__dict__.items()
            if isinstance(key, str) and not key.startswith('_') and not callable(val)
        }


TBaseConfigSubclass = TypeVar('TBaseConfigSubclass', bound='BaseConfig')


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
    eduid_site_name: str = 'eduID'
    eduid_site_url: str = 'https://www.eduid.se'
    eduid_static_url: str = 'https://www.eduid.se/static/'
    safe_relay_domain: str = 'eduid.se'
    # environment=(dev|staging|pro)
    environment: str = 'pro'
    development: bool = False
    # enable disable debug mode
    logging_config: dict = field(default_factory=dict)
    log_level: str = 'INFO'
    log_file: Optional[str] = None
    log_max_bytes: int = 1000000  # 1 MB
    log_backup_count: int = 10  # 10 x 1 MB
    log_format: str = '{asctime} | {levelname:7} | {hostname} | {eppn} | {name:35} | {module} | {message}'
    log_type: List[str] = field(default_factory=lambda: ['stream'])
    logger: Optional[logging.Logger] = None
    redis_config: RedisConfig = field(default_factory=RedisConfig)
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
    token_service_url: str = ''  # the eduid-authn service
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
    available_languages: Dict[str, str] = field(default_factory=lambda: {'en': 'English', 'sv': 'Svenska'})
    supported_languages: Dict[str, str] = field(default_factory=lambda: {'en': 'English', 'sv': 'Svenska'})
    mail_default_from: str = 'no-reply@eduid.se'
    static_url: str = ''
    dashboard_url: str = ''
    reset_passwd_url: str = ''
    default_finish_url: str = ''
    faq_link: str = ''
    students_link: str = ''
    staff_link: str = ''
    technicians_link: str = ''
    tou_url: str = ''
    # set absolute URL so it can be included in emails
    signup_url: str = ''
    # URL to use with VCCS client. BCP is to have an nginx or similar on
    # localhost that will proxy requests to a currently available backend
    # using TLS.
    vccs_url: str = ''
    # Whitelist of URLs that do not need authentication. Unauthenticated requests
    # for these URLs will be served, rather than redirected to the authn service.
    # The list is a list of regex that are matched against the path of the
    # requested URL ex. ^/test$.
    no_authn_urls: list = field(default_factory=lambda: ["^/status/healthy$", "^/status/sanity-check$"])
    # The plugins for pre-authentication actions that need to be loaded
    action_plugins: list = field(default_factory=lambda: ["tou", "mfa"])
    # The current version of the terms of use agreement.
    tou_version: str = '2017-v6'
    current_tou_version: str = '2017-v6'  # backwards compat
    fido2_rp_id: str = ''
    u2f_app_id: str = ''
    stats_host: str = ''
    stats_port: int = 8125
    sentry_dsn: Optional[str] = None
    status_cache_seconds: int = 10
    # code to set in a "magic" cookie to bypass various verifications.
    magic_cookie: Optional[str] = None
    # name of the magic cookie
    magic_cookie_name: Optional[str] = None

    def __post_init__(self):
        # Convert redis_config from dict to the proper dataclass
        if isinstance(self.redis_config, dict):
            self.redis_config = RedisConfig(**self.redis_config)
        # Backwards compat
        if self.redis_host or self.redis_sentinel_hosts:
            self.redis_config = RedisConfig(
                port=self.redis_port,
                db=self.redis_db,
                host=self.redis_host,
                sentinel_hosts=self.redis_sentinel_hosts,
                sentinel_service_name=self.redis_sentinel_service_name,
            )

    @classmethod
    def init_config(
        cls: Type[TBaseConfigSubclass],
        ns: Optional[str] = None,
        app_name: Optional[str] = None,
        test_config: Optional[dict] = None,
        debug: bool = False,
    ) -> TBaseConfigSubclass:
        """
        Initialize configuration with values from etcd (or with test values)
        """
        config: Dict[str, Any] = {
            'debug': debug,
        }
        if test_config:
            # Load init time settings
            config.update(test_config)
            logger.info(f'Using test_config:\n{pprint.pformat(config)}')
            return cls(**config)

        from eduid_common.config.parsers.etcd import EtcdConfigParser

        common_namespace = os.environ.get('EDUID_CONFIG_COMMON_NS', f'/eduid/{ns}/common/')
        common_parser = EtcdConfigParser(common_namespace)
        common_config = common_parser.read_configuration(silent=True)
        config.update(common_config)

        namespace = os.environ.get('EDUID_CONFIG_NS', f'/eduid/{ns}/{app_name}/')
        parser = EtcdConfigParser(namespace)
        # Load optional app specific settings
        app_config = parser.read_configuration(silent=True)
        config.update(app_config)

        # Load optional local settings
        local_config_path = os.environ.get('LOCAL_CFG_FILE')
        if local_config_path is not None and os.path.exists(local_config_path):
            logger.debug(f'LOCAL_CFG_FILE is set and file {local_config_path} exist')
            with open(local_config_path) as f:
                local_config = yaml.safe_load(f)
                for key, value in local_config.items():
                    config[key.lower()] = value
                    logger.debug(f'Added config key {key} from local file')

        # Make sure we don't try to load config keys that are not expected as that will result in a crash
        filtered_config = cls.filter_config(config)
        config_keys = set(config.keys())
        filtered_keys = set(filtered_config.keys())
        if config_keys != filtered_keys:
            logger.warning(f'Keys removed before config loading: {config_keys - filtered_keys}')

        # Save config to a file in /dev/shm for introspection
        fd_int = os.open(f'/dev/shm/{app_name}_config.yaml', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd_int, 'w') as fd:
            fd.write('---\n')
            yaml.safe_dump(filtered_config, fd)

        return cls(**filtered_config)


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
    cookies_samesite_compat: list = field(default_factory=lambda: [('sessid', 'sessid_samesite_compat')])
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
    recaptcha_public_key: str = ''
    recaptcha_private_key: str = ''
