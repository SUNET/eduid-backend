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
from typing import Optional, List, Tuple, Dict, Any


@dataclass(frozen=True)
class CeleryConfig(object):

    accept_content: List[str] = field(default_factory=lambda: ["application/json"])
    broker_url: str = ''
    result_backend: str = ''
    # backwards incompatible setting that the documentation says will be the default in the future
    broker_transport_options: dict = field(default_factory=lambda: {"fanout_prefix": True})
    task_routes: dict = field(default_factory=lambda: {
      'eduid_am.*': {'queue': 'am'},
      'eduid_msg.*': {'queue': 'msg'},
      'eduid_letter_proofing.*': {'queue': 'letter_proofing'}})


@dataclass(frozen=True)
class BaseConfig(object):
    # name of the app, which coincides with its namespace in etcd
    app_name: str = ''
    server_name: str = ''
    devel_mode: bool = False
    development: bool = False
    # enable disable debug mode
    debug: bool = False
    log_level: str = 'INFO'
    # session cookie
    session_cookie_name: str = 'sessid'
    session_cookie_path: str = '/'
    session_cookie_timeout: int = 60      # in minutes
    # the domain for the session cookie. If this is not set, the cookie will
    # be valid for all subdomains of SERVER_NAME.
    session_cookie_domain: str = ''
    session_cookie_secure: bool = True
    session_cookie_httponly: bool = False
    session_cookie_samesite: Optional[str] = None
    # The URL scheme that should be used for URL generation if no URL scheme is
    # available. This defaults to http
    preferred_url_scheme: str = 'https'
    # mongo_uri
    mongo_uri: str = 'mongodb://'
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
    token_service_url: str = ''
    celery_config: CeleryConfig = field(default_factory=CeleryConfig)
    am_broker_url: str = ''
    msg_broker_url: str = ''
    available_languages: Dict[str, str] = field(default_factory=lambda: {
        'en': 'English',
        'sv': 'Svenska'
        })
    mail_default_from: str = 'info@eduid.se'
    eduid_site_url: str = ''
    eduid_static_url: str = ''
    static_url: str = ''
    dashboard_url: str = ''
    reset_passwd_url: str = ''
    # set absolute URL so it can be included in emails
    signup_url: str = ''
    no_authn_urls: list = field(default_factory=lambda: [
        "^/status/healthy$",
        "^/status/sanity-check$"
        ])
    action_plugins: list = field(default_factory=lambda: [
        "tou",
        "mfa"
        ])
    # environment=(dev|staging|pro)
    environment: str = 'dev'
    tou_version: str = '2017-v6'
    current_tou_version: str = '2017-v6'  # backwards compat
    fido2_rp_id: str = ''
    secret_key: str = ''
    logger : Optional[Logger] = None

    def __post_init__(self):
        if isinstance(self.celery_config, dict):
            object.__setattr__(self, 'celery_config', CeleryConfig(**self.celery_config))

    def __getitem__(self, attr: str) -> Any:
        '''
        XXX Once the apps are all accessing configuration as attributes,
            we will be able to remove this method.
        '''
        try:
            return self.__getattribute__(attr.lower())
        except AttributeError:
            raise KeyError(f'{self} has no {attr} attr')

    @classmethod
    def defaults(cls, transform_key: callable = lambda x: x) -> dict:
        return {transform_key(key): val for key, val in cls.__dict__.items()
                  if isinstance(key, str) and not key.startswith('__') and not callable(val)}

    def to_dict(self, transform_key: callable = lambda x: x) -> dict:
        return {transform_key(key): val for key, val in self.__dict__.items()
                  if isinstance(key, str) and not key.startswith('__') and not callable(val)}

    @classmethod
    def init_config(cls, debug: bool = True, test_config: Optional[dict] = None) -> BaseConfig:
        """
        Initialize configuration wth values from etcd
        """
        config : Dict[str, Any] = {'debug': debug}
        if test_config is not None:
            # Load init time settings
            config.update(test_config)
        else:
            from eduid_common.config.parsers.etcd import EtcdConfigParser

            common_namespace = os.environ.get('EDUID_CONFIG_COMMON_NS', '/eduid/webapp/common/')
            common_parser = EtcdConfigParser(common_namespace)
            config.update(common_parser.read_configuration(silent=True))

            namespace = os.environ.get('EDUID_CONFIG_NS', f'/eduid/webapp/{cls.app_name}/')
            parser = EtcdConfigParser(namespace)
            # Load optional app specific settings
            config.update(parser.read_configuration(silent=True))

        return cls(**config)


class FlaskConfig(BaseConfig):
    env : str = 'production'
    propagate_exceptions : Optional[bool] = None
    preserve_context_on_exception : bool = False
