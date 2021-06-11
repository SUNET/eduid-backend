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

import logging
import re
from abc import ABCMeta
from typing import Callable, Union
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from flask import current_app
from werkzeug.wrappers import Response
from werkzeug.wsgi import get_current_url

from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.utils import urlappend
from eduid.webapp.common.session import session
from eduid.webapp.common.session.redis_session import NoSessionDataFoundException

no_context_logger = logging.getLogger(__name__)


class AuthnBaseApp(EduIDBaseApp, metaclass=ABCMeta):
    """
    WSGI middleware that checks whether the request is authenticated,
    and in case it isn't, redirects to the authn service.
    """

    def __call__(self, environ: dict, start_response: Callable) -> Union[Response, list]:
        next_url = get_current_url(environ)
        next_path = list(urlparse(next_url))[2]
        allowlist = self.conf.no_authn_urls
        no_context_logger.debug(f'Checking if URL path {next_path} matches no auth allow list: {allowlist}')
        for regex in allowlist:
            m = re.match(regex, next_path)
            if m is not None:
                no_context_logger.debug(f'{next_path} matched allow list')
                return super(AuthnBaseApp, self).__call__(environ, start_response)

        with self.request_context(environ):
            try:
                if session.common.eppn and session.common.is_logged_in:
                    return super(AuthnBaseApp, self).__call__(environ, start_response)
            except NoSessionDataFoundException:
                current_app.logger.info('Caught a NoSessionDataFoundException - forcing the user to authenticate')
                del environ['HTTP_COOKIE']  # Force relogin
                # If HTTP_COOKIE is not removed self.request_context(environ) below
                # will try to look up the Session data in the backend

        ts_url = urlappend(self.conf.token_service_url, 'login')

        params = {'next': next_url}

        url_parts = list(urlparse(ts_url))
        query = parse_qs(url_parts[4])
        query.update(params)

        url_parts[4] = urlencode(query)
        location = urlunparse(url_parts)

        headers = [('Location', location)]
        start_response('302 Found', headers)
        return []
