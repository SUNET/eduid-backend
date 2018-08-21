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

try:
    import urlparse
except ImportError:
    from urllib import parse as urlparse

import re
import logging
from urllib import urlencode

from werkzeug import get_current_url
from werkzeug.http import parse_cookie, dump_cookie
from flask import Flask, session, current_app, request
from eduid_common.api.session import NoSessionDataFoundException
from eduid_common.api.utils import urlappend

no_context_logger = logging.getLogger(__name__)


class AuthnApp(Flask):
    """
    WSGI middleware that checks whether the request is authenticated,
    and in case it isn't, redirects to the authn service.
    """
    def __call__(self, environ, start_response):
        next_url = get_current_url(environ)
        next_path = list(urlparse.urlparse(next_url))[2]
        whitelist = self.config.get('NO_AUTHN_URLS', [])
        no_context_logger.debug('No auth whitelist: {}'.format(whitelist))
        for regex in whitelist:
            m = re.match(regex, next_path)
            if m is not None:
                no_context_logger.debug('{} matched whitelist'.format(next_path))
                return super(AuthnApp, self).__call__(environ, start_response)

        with self.request_context(environ):
            try:
                if session.get('user_eppn'):
                    return super(AuthnApp, self).__call__(environ, start_response)
            except NoSessionDataFoundException:
                current_app.logger.info('Caught a NoSessionDataFoundException - forcing the user to authenticate')
                del environ['HTTP_COOKIE']  # Force relogin
                # If HTTP_COOKIE is not removed self.request_context(environ) below
                # will try to look up the Session data in the backend

        ts_url = urlappend(self.config.get('TOKEN_SERVICE_URL'), 'login')

        params = {'next': next_url}

        url_parts = list(urlparse.urlparse(ts_url))
        query = urlparse.parse_qs(url_parts[4])
        query.update(params)

        url_parts[4] = urlencode(query)
        location = urlparse.urlunparse(url_parts)

        with self.request_context(environ):
            cookie_name = self.config.get('SESSION_COOKIE_NAME')
            headers = [ ('Location', location) ]
            cookie = dump_cookie(cookie_name, session._session.token,
                                 max_age=int(self.config.get('PERMANENT_SESSION_LIFETIME')),
                                 path=self.config.get('SESSION_COOKIE_PATH'),
                                 domain=self.config.get('SESSION_COOKIE_DOMAIN'),
                                 secure=self.config.get('SESSION_COOKIE_SECURE'),
                                 httponly=self.config.get('SESSION_COOKIE_HTTPONLY'))
            session.persist()
            headers.append(('Set-Cookie', cookie))

            start_response('302 Found', headers)
            return []


class UnAuthnApp(Flask):
    """
    WSGI middleware for unauthenticated apps - e.g., signup.
    It checks whether the request has a session cookie,
    and in case it hasn't, adds one and replays the request.
    """
    def __call__(self, environ, start_response):
        next_url = get_current_url(environ)

        with self.request_context(environ):
            cookie_name = self.config.get('SESSION_COOKIE_NAME', 'signup-sessid')
            if cookie_name not in request.cookies:
                cookie = dump_cookie(cookie_name, session._session.token,
                                     max_age=int(self.config.get('PERMANENT_SESSION_LIFETIME')),
                                     path=self.config.get('SESSION_COOKIE_PATH'),
                                     domain=self.config.get('SESSION_COOKIE_DOMAIN'),
                                     secure=self.config.get('SESSION_COOKIE_SECURE'),
                                     httponly=self.config.get('SESSION_COOKIE_HTTPONLY'))
                session.persist()
                headers = [ ('Location', next_url) ]
                headers.append(('Set-Cookie', cookie))
                start_response('302 Found', headers)
                return []
        
        return super(UnAuthnApp, self).__call__(environ, start_response)
