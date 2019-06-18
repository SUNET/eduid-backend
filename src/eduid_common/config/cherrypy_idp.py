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
from typing import Optional, List, Tuple

from .base import BaseConfig


@dataclass(frozen=True)
class IdPConfig(BaseConfig):
    """
    Configuration for the IdP
    """
    # session cookie
    SESSION_COOKIE_PERSISTENT: bool = True
    SESSION_COOKIE_LOCKING: str = 'explicit'
    # Secret key
    SECRET_KEY: Optional[str] = None
    # Logging
    LOG_LEVEL: str = 'DEBUG'
    # IdP specific
    SYSLOG_DEBUG: bool = False
    NUM_THREADS: int = 8
    LOGDIR: Optional[str] = None
    LOGFILE: Optional[str] = None
    # syslog socket to log to (/dev/log maybe)
    SYSLOG_SOCKET: Optional[str] = None
    # IP address to listen on.
    LISTEN_ADDR: str = '0.0.0.0'
    # The port the IdP authentication should listen on (integer).
    LISTEN_PORT: int = 8088
    # pysaml2 configuration file. Separate config file with SAML related parameters.
    PYSAML2_CONFIG: str = 'eduid_common.authn.idp_conf'
    # SAML F-TICKS user anonymization key. If this is set, the IdP will log FTICKS data
    # on every login.
    FTICKS_SECRET_KEY: Optional[str] = None
    # Get SAML F-TICKS format string.
    FTICKS_FORMAT_STRING: str = 'F-TICKS/SWAMID/2.0#TS={ts}#RP={rp}#AP={ap}#PN={pn}#AM={am}#'
    # directory for local static files
    STATIC_DIR: Optional[str] = None
    # URL to static resources that can be used in templates
    STATIC_LINK: str = '#'
    # one of cherrypy.wsgiserver.ssl_adapters
    SSL_ADAPTER: str = 'builtin'
    # SSL certificate filename (None == SSL disabled)
    SERVER_CERT: Optional[str] = None
    # SSL private key filename (None == SSL disabled)
    SERVER_KEY: Optional[str] = None

    # SSL certificate chain filename, or None
    CERT_CHAIN: Optional[str] = None
    #  UserDB database name. eduid_am for old userdb, eduid_userdb for new
    USERDB_MONGO_DATABASE: str = 'eduid_am'
    # MongoDB connection URI (string). See MongoDB documentation for details.
    MONGO_URI: Optional[str] = None
    # MongoDB connection URI (string) for PySAML2 SSO sessions.
    SSO_SESSION_MONGO_URI: Optional[str] = None
    # Lifetime of SSO session (in minutes).
    # If a user has an active SSO session, they will get SAML assertions made
    # without having to authenticate again (unless SP requires it through
    # ForceAuthn).
    # The total time a user can access a particular SP would therefor be
    # this value, plus the pysaml2 lifetime of the assertion.
    SSO_SESSION_LIFETIME: int = 15
    # Raven DSN (string) for logging exceptions to Sentry.
    RAVEN_DSN: Optional[str] = None
    # List of Python packages [("name","path") ... ]̣ with content resources
    CONTENT_PACKAGES: List[Tuple[str]] = field(default_factory=list)
    # Verify request signatures, if they exist.
    # This defaults to False since it is a trivial DoS to consume all the IdP:s
    # CPU resources if this is set to True.
    VERIFY_REQUEST_SIGNATURES: bool = False
    # Get list of usernames valid for use with the /status URL.
    # If this list is ['*'], all usernames are allowed for /status.
    STATUS_TEST_USERNAMES: List[str] =  field(default_factory=list)
    # URL (string) for use in simple templating of login.html.
    SIGNUP_LINK: str = '#'
    # URL (string) for use in simple templating of forbidden.html.
    DASHBOARD_LINK: str = '#'
    # URL (string) for use in simple templating of login.html.
    PASSWORD_RESET_LINK: str = '#'
    # More links
    TECHNICIANS_LINK: str = '#'
    STUDENT_LINK: str = '#'
    STAFF_LINK: str = '#'
    FAQ_LINK: str = '#'
    # Default language code to use when looking for web pages ('en').
    DEFAULT_LANGUAGE: str = 'en'
    # Base URL of the IdP. The default base URL is constructed from the
    # Request URI, but for example if there is a load balancer/SSL
    # terminator in front of the IdP it might be required to specify
    # the URL of the service.
    BASE_URL: Optional[str] = None
    # The scope to append to any unscoped eduPersonPrincipalName
    # attributes found on users in the userdb.
    DEFAULT_EPPN_SCOPE: Optional[str] = None
    # Disallow login for a user after N failures in a given month.
    # This is said to be an imminent Kantara requirement.
    # Kantara 30-day bad authn limit is 100
    MAX_AUTHN_FAILURES_PER_MONTH: int = 50
    # Lifetime of state kept in IdP login phase.
    # This is the time, in minutes, a user has to complete the login phase.
    # After this time, login cannot complete because the SAMLRequest, RelayState
    # and possibly other needed information will be forgotten.
    LOGIN_STATE_TTL: int = 5
    # Add a default eduPersonScopedAffiliation if none is returned from the
    # attribute manager.
    DEFAULT_SCOPED_AFFILIATION: Optional[str] = None
    # URL to use with VCCS client. BCP is to have an nginx or similar on
    # localhost that will proxy requests to a currently available backend
    # using TLS.
    VCCS_URL: str = 'http://localhost:8550/'
    INSECURE_COOKIES: bool = False
    # URI of the actions app.
    ACTIONS_APP_URI: Optional[str] = 'http://actions.example.com/'
    # The plugins for pre-authentication actions that need to be loaded
    ACTION_PLUGINS: List[str] = field(default_factory=list)
    # The current version of the terms of use agreement.
    TOU_VERSION: str = 'version1'
    # The interval which a user needs to reaccept an already accepted ToU (in seconds)
    TOU_REACCEPT_INTERVAL: int = 94608000
    # Name of cookie used to persist session information in the users browser.
    SHARED_SESSION_COOKIE_NAME: str = 'sessid'
    # Key to decrypt shared sessions.
    SHARED_SESSION_SECRET_KEY: Optional[str] = None
    # TTL for shared sessions.
    SHARED_SESSION_TTL: int = 300


def init_config(test_config: Optional[dict] = None) -> IdPConfig:
    """
    Initialize configuration wth values from etcd
    """
    config = {}
    if test_config is not None:
        # Load init time settings
        config.update(test_config)
    else:
        from eduid_common.config.parsers.etcd import EtcdConfigParser

        common_namespace = os.environ.get('EDUID_CONFIG_COMMON_NS', '/eduid/webapp/common/')
        common_parser = EtcdConfigParser(common_namespace)
        config.update(common_parser.read_configuration(silent=True))

        namespace = os.environ.get('EDUID_CONFIG_NS', '/eduid/webapp/idp/')
        parser = EtcdConfigParser(namespace)
        # Load optional app specific settings
        config.update(parser.read_configuration(silent=True))

    idp_config = IdPConfig(**config)

    return idp_config
