#
# Copyright (c) 2013 NORDUnet A/S
# Copyright 2012 Roland Hedberg. All rights reserved.
# All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

"""
Miscellaneous HTTP related functions.
"""
from __future__ import annotations

import pprint
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple, Type

from flask import make_response, redirect, request
from saml2 import BINDING_HTTP_REDIRECT
from werkzeug.exceptions import BadRequest, InternalServerError
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.common.api.sanitation import SanitationProblem, Sanitizer
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.settings.common import IdPConfig


@dataclass
class HttpArgs:
    """ Dataclass to remove the ambiguities of pysaml2:s apply_binding() return value """

    method: str
    url: str
    headers: Sequence[Tuple[str, str]]
    body: Optional[str]

    @classmethod
    def from_pysaml2_dict(cls: Type[HttpArgs], http_args: Dict[str, Any]) -> HttpArgs:
        # Parse the parts of http_args we know how to parse, and then warn about any remains.
        if 'status' in http_args and http_args["status"] != 200:
            current_app.logger.warning(f'Ignoring status in http_args: {http_args["status"]}')
        method = http_args.pop('method')
        url = http_args.pop('url')
        message = http_args.pop('data')
        status = http_args.pop('status', '200 Ok')
        headers = http_args.pop('headers', [])
        headers_lc = [x[0].lower() for x in headers]
        if 'content-type' not in headers_lc:
            _content_type = http_args.pop('content', 'text/html')
            headers.append(('Content-Type', _content_type))

        if http_args != {}:
            current_app.logger.debug(
                f'Unknown HTTP args when creating {repr(status)} response :\n{pprint.pformat(http_args)}'
            )

        return cls(method=method, url=url, headers=headers, body=message)

    @property
    def redirect_url(self) -> Optional[str]:
        """
        Get the destination URL for a redirect.

        Use the header Location first, and secondly 'url' from http_args.
        """
        for k, v in self.headers:
            if k.lower() == 'location':
                return v
        return self.url


def create_html_response(binding: str, http_args: HttpArgs) -> WerkzeugResponse:
    """
    Create a HTML response based on parameters compiled by pysaml2 functions
    like apply_binding().

    :param binding: SAML binding
    :param http_args: response data
    :return: HTML response
    """
    if binding == BINDING_HTTP_REDIRECT:
        if http_args.method != 'GET':
            current_app.logger.warning(f'BINDING_HTTP_REDIRECT method is not GET ({http_args.method})')
        location = http_args.redirect_url
        current_app.logger.debug(f'Binding {binding} redirecting to {repr(location)}')
        if not location:
            raise InternalServerError('No redirect destination')
        if http_args.url:
            if not location.startswith(http_args.url):
                current_app.logger.warning(f'There is another "url" in args: {http_args.url} (location: {location})')
        return redirect(location)

    message = b''
    if isinstance(http_args.body, bytes):
        message = http_args.body
    elif http_args.body is not None:
        message = bytes(http_args.body, 'utf-8')

    response = make_response(message)
    for k, v in http_args.headers:
        _old_v = response.headers.get(k)
        if v != _old_v:
            current_app.logger.debug(f'Changing response header {repr(k)} from {repr(_old_v)} -> {repr(v)}')
            response.headers[k] = v
    return response


def get_post() -> Dict[str, Any]:
    """
    Return the parsed query string equivalent from a HTML POST request.

    When the method is POST the query string will be sent in the HTTP request body.

    :return: query string
    """
    return _sanitise_items(request.form)


def _sanitise_items(data: Mapping[str, Any]) -> Dict[str, str]:
    res = dict()
    san = Sanitizer()
    for k, v in data.items():
        try:
            safe_k = san.sanitize_input(k, logger=current_app.logger, content_type='text/plain')
            if safe_k != k:
                raise BadRequest()
            safe_v = san.sanitize_input(v, logger=current_app.logger, content_type='text/plain')
        except SanitationProblem:
            current_app.logger.exception(f'There was a problem sanitizing inputs')
            raise BadRequest()
        res[str(safe_k)] = str(safe_v)
    return res


# ----------------------------------------------------------------------------
# Cookie handling
# ----------------------------------------------------------------------------
def read_cookie(name: str) -> Optional[str]:
    """
    Read a browser cookie.

    :returns: string with cookie content, or None
    """
    cookies = request.cookies
    current_app.logger.debug(f'Reading cookie(s): {cookies}')
    cookie = cookies.get(name)
    if not cookie:
        current_app.logger.debug(f'No IdP SSO cookie ({name}) found')
        return None
    return cookie


def set_sso_cookie(value: str, response: WerkzeugResponse) -> WerkzeugResponse:
    """
    Ask the browser to store an SSO cookie.

    :param value: The value to assign to the cookie
    :param response: Flask response object
    """
    response.set_cookie(
        key=current_app.conf.sso_cookie.key,
        value=value,
        domain=current_app.conf.sso_cookie.domain,
        path=current_app.conf.sso_cookie.path,
        secure=current_app.conf.sso_cookie.secure,
        httponly=current_app.conf.sso_cookie.httponly,
        samesite=current_app.conf.sso_cookie.samesite,
        max_age=current_app.conf.sso_cookie.max_age_seconds,
    )
    _cookie = response.headers.get('Set-Cookie')
    current_app.logger.debug(f'Set SSO cookie {_cookie}')
    return response


def parse_query_string() -> Dict[str, str]:
    """
    Parse HTML request query string into a dict like

    {'Accept': string,
     'Host': string,
    }

    NOTE: Only the first header value for each header is included in the result.

    :return: parsed query string
    """
    args = _sanitise_items(request.args)
    res = {}
    for k, v in args.items():
        if isinstance(v, list):
            res[k] = v[0]
        else:
            res[k] = v
    return res


def get_default_template_arguments(config: IdPConfig) -> Dict[str, str]:
    """
    :return: header links
    """
    return {
        'dashboard_link': config.dashboard_link,
        'signup_link': config.signup_link,
        'student_link': config.student_link,
        'technicians_link': config.technicians_link,
        'staff_link': config.staff_link,
        'faq_link': config.faq_link,
        'password_reset_link': config.password_reset_link,
        'static_link': config.static_link,
    }
