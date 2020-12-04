# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
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
Configuration (file) handling for the eduID idp app.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from eduid_common.config.base import CookieConfig, FlaskConfig


@dataclass
class IdPConfig(FlaskConfig):
    """
    Configuration for the idp app
    """

    app_name: str = 'idp'
    # pysaml2 configuration file. Separate config file with SAML related parameters.
    pysaml2_config: str = 'eduid_common.authn.idp_conf'
    # SAML F-TICKS user anonymization key. If this is set, the IdP will log FTICKS data
    # on every login.
    fticks_secret_key: Optional[str] = None
    # Get SAML F-TICKS format string.
    fticks_format_string: str = 'F-TICKS/SWAMID/2.0#TS={ts}#RP={rp}#AP={ap}#PN={pn}#AM={am}#'
    # directory for local static files
    static_dir: Optional[str] = None
    # URL to static resources that can be used in templates
    static_link: str = '#'
    #  UserDB database name. eduid_am for old userdb, eduid_userdb for new
    userdb_mongo_database: str = 'eduid_am'
    # MongoDB connection URI (string). See MongoDB documentation for details.
    userdb_mongo_uri: Optional[str] = None
    authn_info_mongo_uri: Optional[str] = None
    # MongoDB connection URI (string) for PySAML2 SSO sessions.
    sso_session_mongo_uri: Optional[str] = None
    # Lifetime of SSO session (in minutes).
    # If a user has an active SSO session, they will get SAML assertions made
    # without having to authenticate again (unless SP requires it through
    # ForceAuthn).
    # The total time a user can access a particular SP would therefor be
    # this value, plus the pysaml2 lifetime of the assertion.
    sso_session_lifetime: int = 600
    # Verify request signatures, if they exist.
    # This defaults to False since it is a trivial DoS to consume all the IdP:s
    # CPU resources if this is set to True.
    verify_request_signatures: bool = False
    # Get list of usernames valid for use with the /status URL.
    # If this list is ['*'], all usernames are allowed for /status.
    status_test_usernames: List[str] = field(default_factory=list)
    # URL (string) for use in simple templating of login.html.
    signup_link: str = '#'
    # URL (string) for use in simple templating of forbidden.html.
    dashboard_link: str = '#'
    # URL (string) for use in simple templating of login.html.
    password_reset_link: str = '#'
    # More links
    technicians_link: str = '#'
    student_link: str = '#'
    staff_link: str = '#'
    faq_link: str = '#'
    # Default language code to use when looking for web pages ('en').
    default_language: str = 'en'
    # Base URL of the IdP. The default base URL is constructed from the
    # Request URI, but for example if there is a load balancer/SSL
    # terminator in front of the IdP it might be required to specify
    # the URL of the service.
    base_url: Optional[str] = None
    # The scope to append to any unscoped eduPersonPrincipalName
    # attributes found on users in the userdb.
    default_eppn_scope: Optional[str] = None
    # Default country code to use in attribute release as c - ISO_COUNTRY_CODE
    default_country_code: str = 'se'
    # Default country to use in attribute release as co - ISO_COUNTRY_NAME
    default_country: str = 'Sweden'
    # Disallow login for a user after N failures in a given month.
    # This is said to be an imminent Kantara requirement.
    # Kantara 30-day bad authn limit is 100
    max_auhtn_failures_per_month: int = 50
    max_authn_failures_per_month: int = 50
    # Lifetime of state kept in IdP login phase.
    # This is the time, in minutes, a user has to complete the login phase.
    # After this time, login cannot complete because the SAMLRequest, RelayState
    # and possibly other needed information will be forgotten.
    login_state_ttl: int = 5
    # URL to use with VCCS client. BCP is to have an nginx or similar on
    # localhost that will proxy requests to a currently available backend
    # using TLS.
    vccs_url: str = 'http://localhost:8550/'
    # URI of the actions app.
    actions_app_uri: Optional[str] = 'http://actions.example.com/'
    # The plugins for pre-authentication actions that need to be loaded
    action_plugins: List[str] = field(default_factory=list)
    # The current version of the terms of use agreement.
    tou_version: str = 'version1'
    # The interval which a user needs to reaccept an already accepted ToU (in seconds)
    tou_reaccept_interval: int = 94608000
    # Name of cookie used to persist session information in the users browser.
    shared_session_cookie_name: str = 'sessid'
    # Cookie for IdP-specific session allowing users to SSO
    sso_cookie: CookieConfig = field(default_factory=lambda: CookieConfig(key='idpauthn'))
    # Legacy parameters for the SSO cookie. Keep in sync with sso_cookie above until removed!
    sso_cookie_name: str = 'idpauthn'
    sso_cookie_domain: Optional[str] = None
    session_cookie_timeout: int = 60  # in minutes
    preferred_url_scheme: str = 'http'
    # TTL for shared sessions.
    shared_session_ttl: int = 300
    http_headers: str = "Content-Security-Policy:default-src 'self'; script-src 'self' 'unsafe-inline', X-Frame-Options:DENY"
    privacy_link: str = "http://html.eduid.docker/privacy.html"
    # List in order of preference
    supported_digest_algorithms: List[str] = field(default_factory=lambda: ['http://www.w3.org/2001/04/xmlenc#sha256'])
    # List in order of preference
    supported_signing_algorithms: List[str] = field(
        default_factory=lambda: ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']
    )
    eduperson_targeted_id_secret_key: str = ''

    def __post_init__(self):
        super().__post_init__()
        # Convert sso_cookie from dict to the proper dataclass
        if isinstance(self.sso_cookie, dict):
            self.sso_cookie = CookieConfig(**self.sso_cookie)
        elif self.sso_cookie_name:
            # let legacy parameters override as long as they are present
            self.sso_cookie = CookieConfig(key=self.sso_cookie_name, domain=self.sso_cookie_domain)
