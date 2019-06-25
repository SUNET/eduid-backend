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
# Author : Fredrik Thulin <fredrik@thulin.net>
#
"""
Configuration (file) handling for eduID IdP.
"""

from dataclasses import dataclass, field
import os
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
    DEVEL_MODE: bool = False
    DEVELOPMENT: bool = False
    # enable disable debug mode
    DEBUG: bool = False
    # session cookie
    SESSION_COOKIE_NAME: str = 'sessid'
    SESSION_COOKIE_PATH: str = '/'
    SESSION_COOKIE_TIMEOUT: int = 60      # in minutes
    # the domain for the session cookie. If this is not set, the cookie will
    # be valid for all subdomains of SERVER_NAME.
    SESSION_COOKIE_DOMAIN: str = ''
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = False
    # The URL scheme that should be used for URL generation if no URL scheme is
    # available. This defaults to http
    PREFERRED_URL_SCHEME: str = 'https'
    # Redis config
    # The Redis host to use for session storage.
    REDIS_HOST: Optional[str] = None
    # The port of the Redis server (integer).
    REDIS_PORT: int = 6379
    # The Redis database number (integer).
    REDIS_DB: int = 0
    # Redis sentinel hosts, comma separated
    REDIS_SENTINEL_HOSTS: Optional[List[str]] = None
    # The Redis sentinel 'service name'.
    REDIS_SENTINEL_SERVICE_NAME: str = 'redis-cluster'
    SAML2_LOGOUT_REDIRECT_URL: str = 'https://eduid.se/'
    TOKEN_SERVICE_URL: str = ''
    CELERY_CONFIG: CeleryConfig = field(default_factory=CeleryConfig)
    AVAILABLE_LANGUAGES: Dict[str, str] = field(default_factory=lambda: {
        'en': 'English',
        'sv': 'Svenska'
        })
    MAIL_DEFAULT_FROM: str = 'info@eduid.se'
    EDUID_SITE_URL: str = ''
    EDUID_STATIC_URL: str = ''
    STATIC_URL: str = ''
    DASHBOARD_URL: str = ''
    RESET_PASSWD_URL: str = ''
    # set absolute URL so it can be included in emails
    SIGNUP_URL: str = ''
    NO_AUTHN_URLS: list = field(default_factory=lambda: [
        "^/status/healthy$",
        "^/status/sanity-check$"
        ])
    ACTION_PLUGINS: list = field(default_factory=lambda: [
        "tou",
        "mfa"
        ])
    # ENVIRONMENT=(dev|staging|pro)
    ENVIRONMENT: str = 'dev'
    TOU_VERSION: str = '2017-v6'
    CURRENT_TOU_VERSION: str = '2017-v6'  # backwards compat
    FIDO2_RP_ID: str = ''
    SECRET_KEY: str = ''

    def __post_init__(self):
        object.__setattr__(self, 'CELERY_CONFIG', CeleryConfig(**self.CELERY_CONFIG))

    def __getattribute__(self, attr: str, default: Any = None) -> Any:
        try:
            return super(BaseConfig, self).__getattribute__(attr)
        except AttributeError:
            # Allow the IdP to keep using lower case config keys
            try:
                return super(BaseConfig, self).__getattribute__(attr.upper())
            except AttributeError:
                if default is not None:
                    return default
                raise

    def __getitem__(self, attr: str) -> Any:
        '''
        XXX Once the apps are all accessing configuration as attributes,
            we will be able to remove this method.
        '''
        try:
            return self.__getattribute__(attr)
        except AttributeError:
            raise KeyError(f'{self} has no {attr} attr')
