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
import urlparse
from urllib import urlencode

from werkzeug import get_current_url
from werkzeug.http import parse_cookie
from flask import Flask


class AuthnApp(Flask):
    """
    """
    def __call__(self, environ, start_response):
        cookie = parse_cookie(environ)
        cookie_name = self.config.get('SESSION_COOKIE_NAME')
        if cookie and cookie_name in cookie:
            return super(AuthnApp, self).__call__(environ, start_response)
        ts_url = self.config.get('TOKEN_SERVICE_URL')
        next_url = get_current_url(environ)

        params = {'next': next_url}

        url_parts = list(urlparse.urlparse(ts_url))
        query = urlparse.parse_qs(url_parts[4])
        query.update(params)

        url_parts[4] = urlencode(query)
        location = urlparse.urlunparse(url_parts)

        headers = [ ('Location', location) ]
        start_response('302 Found', headers)
        return []
