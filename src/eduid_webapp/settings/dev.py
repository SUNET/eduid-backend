# -*- coding: utf-8 -*-

#
# Copyright (c) 2016 NORDUnet A/S
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

# ==============#
# Flask config #
# ==============#

# enable/disable debug mode
DEBUG = True

# the secret key
SECRET_KEY = 'development'

# the name of the session cookie
SESSION_COOKIE_NAME = 'sessid'

# the domain for the session cookie. If this is not set, the cookie will
# be valid for all subdomains of SERVER_NAME.
SESSION_COOKIE_DOMAIN = 'docker'

# The URL scheme that should be used for URL generation if no URL scheme is
# available. This defaults to http.
PREFERRED_URL_SCHEME = 'http'


# ================#
# mongodb config #
# ================#

MONGO_URI = 'mongodb://mongodb.docker:27017/'


# ==============#
# redis config #
# ==============#

REDIS_HOST = 'redis.docker'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_SENTINEL_HOSTS = ''
REDIS_SENTINEL_SERVICE_NAME = ''


# =======#
# SAML2 #
# =======#

SAML2_LOGIN_REDIRECT_URL = '/'
SAML2_SETTINGS_MODULE = 'eduid_webapp.authn/src/eduid_webapp/authn/tests/saml2_settings.py'
SAML2_LOGOUT_REDIRECT_URL = 'http://html.docker/'
SAML2_USER_MAIN_ATTRIBUTE = 'eduPersonPrincipalName'
SAML2_STRIP_SAML_USER_SUFFIX = '@local.eduid.se'
