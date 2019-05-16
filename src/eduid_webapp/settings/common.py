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

from __future__ import absolute_import
from os import path, sep

from typing import List


# ==============#
# Flask config #
# ==============#

# enable/disable debug mode
DEBUG = False

# enable/disable testing mode
TESTING = False

# explicitly enable or disable the propagation of exceptions.
# If not set or explicitly set to None this is implicitly true if either
# TESTING or DEBUG is true.
PROPAGATE_EXCEPTIONS = None

# By default if the application is in debug mode the request context is not
# popped on exceptions to enable debuggers to introspect the data. This can be
# disabled by this key. You can also use this setting to force-enable it for non
# debug execution which might be useful to debug production applications (but
# also very risky).
PRESERVE_CONTEXT_ON_EXCEPTION = False

# the secret key
SECRET_KEY = None

# the name of the session cookie
SESSION_COOKIE_NAME = 'sessid'

# the domain for the session cookie. If this is not set, the cookie will
# be valid for all subdomains of SERVER_NAME.
SESSION_COOKIE_DOMAIN = 'eduid.se'

# the path for the session cookie. If this is not set the cookie will be valid
# for all of APPLICATION_ROOT or if that is not set for '/'.
SESSION_COOKIE_PATH = '/'

# controls if the cookie should be set with the httponly flag. Defaults to True
SESSION_COOKIE_HTTPONLY = True

# controls if the cookie should be set with the secure flag. Defaults to False
SESSION_COOKIE_SECURE = False

# the lifetime of a permanent session as datetime.timedelta object.
# Starting with Flask 0.8 this can also be an integer representing seconds.
PERMANENT_SESSION_LIFETIME = 3600

# enable/disable x-sendfile
# USE_X_SENDFILE = False

# the name of the logger
LOGGER_NAME = 'eduid_webapp'

# the name and port number of the server. Required for subdomain support (e.g.: 'myapp.dev:5000') Note that localhost
# does not support subdomains so setting this to “localhost” does not help. Setting a SERVER_NAME also by default
# enables URL generation without a request context but with an application context.
SERVER_NAME = None

# If the application does not occupy a whole domain or subdomain this can be set to the path where the application is
# configured to live. This is for session cookie as path value. If domains are used, this should be None.
APPLICATION_ROOT = None

# If set to a value in bytes, Flask will reject incoming requests with a
# content length greater than this by returning a 413 status code.
# MAX_CONTENT_LENGTH

# Default cache control max age to use with send_static_file() (the default
# static file handler) and send_file(), in seconds. Override this value on a
# per-file basis using the get_send_file_max_age() hook on Flask or Blueprint,
# respectively. Defaults to 43200 (12 hours).
SEND_FILE_MAX_AGE_DEFAULT = 43200

# If this is set to True Flask will not execute the error handlers of HTTP
# exceptions but instead treat the exception like any other and bubble it through
# the exception stack. This is helpful for hairy debugging situations where you
# have to find out where an HTTP exception is coming from.
TRAP_HTTP_EXCEPTIONS = False

# Werkzeug’s internal data structures that deal with request specific data
# will raise special key errors that are also bad request exceptions. Likewise
# many operations can implicitly fail with a BadRequest exception for
# consistency. Since it’s nice for debugging to know why exactly it failed this
# flag can be used to debug those situations. If this config is set to True you
# will get a regular traceback instead.
TRAP_BAD_REQUEST_ERRORS = False

# The URL scheme that should be used for URL generation if no URL scheme is
# available. This defaults to http.
PREFERRED_URL_SCHEME = 'https'

# By default Flask serialize object to ascii-encoded JSON. If this is set to
# False Flask will not encode to ASCII and output strings as-is and return
# unicode strings. jsonfiy will automatically encode it in utf-8 then for
# transport for instance.
JSON_AS_ASCII = False

# By default Flask will serialize JSON objects in a way that the keys are
# ordered. This is done in order to ensure that independent of the hash seed of
# the dictionary the return value will be consistent to not trash external HTTP
# caches. You can override the default behavior by changing this variable. This
# is not recommended but might give you a performance improvement on the cost of
# cachability.
# JSON_SORT_KEYS = True

# If this is set to True (the default) jsonify responses will be pretty printed
# if they are not requested by an XMLHttpRequest object (controlled by the
# X-Requested-With header)
# JSONIFY_PRETTYPRINT_REGULAR

# Whitelist of URLs that do not need authentication. Unauthenticated requests
# for these URLs will be served, rather than redirected to the authn service.
# The list is a list of regex that are matched against the path of the
# requested URL ex. ^/test$.
NO_AUTHN_URLS: List[str] = []


# ================#
#  mongodb config #
# ================#

MONGO_URI = 'mongodb://'


# ==============#
#  redis config #
# ==============#

REDIS_HOST = ''
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_SENTINEL_HOSTS = ''
REDIS_SENTINEL_SERVICE_NAME = ''


# =======#
#  SAML2 #
# =======#

SAML2_LOGIN_REDIRECT_URL = '/'
SAML2_SETTINGS_MODULE = ''
SAML2_LOGOUT_REDIRECT_URL = 'https://www.eduid.se/'
SAML2_USER_MAIN_ATTRIBUTE = 'eduPersonPrincipalName'
SAML2_STRIP_SAML_USER_SUFFIX = '@eduid.se'

# ===============#
#  AUTHN SERVICE #
# ===============#

TOKEN_SERVICE_URL = 'https://'
SAFE_RELAY_DOMAIN = 'eduid.se'

# ===============#
#  TEMPLATE DATA #
# ===============#
EDUID_SITE_NAME = 'eduID'
EDUID_SITE_URL = 'https://www.eduid.se'
EDUID_STATIC_URL = 'https://www.eduid.se/static/'

# ===============#
#  BABEL         #
# ===============#

# Try to guess the language from the user accept header the browser transmits. The best match wins.
SUPPORTED_LANGUAGES = ['sv', 'en']

# The translations directory resides on the same level as the settings directory
BABEL_TRANSLATION_DIRECTORIES = path.join(sep.join(path.dirname(path.abspath(__file__)).split(sep)[:-1]),
                                          'translations')

# ===============#
#  MAIL          #
# ===============#
MAIL_DEFAULT_FROM = 'no-reply@eduid.se'
