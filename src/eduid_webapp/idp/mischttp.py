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

import logging
import pprint
from logging import Logger
from typing import Any, Dict, Mapping, Optional

from flask import Response as FlaskResponse
from flask import redirect, request
from saml2 import BINDING_HTTP_REDIRECT
from werkzeug.exceptions import BadRequest
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid_common.api.sanitation import SanitationProblem, Sanitizer


def create_html_response(binding: str, http_args: dict, logger: Logger) -> WerkzeugResponse:
    """
    Create a HTML response based on parameters compiled by pysaml2 functions
    like apply_binding().

    :param binding: SAML binding
    :param http_args: response data
    :param logger: logging logger

    :return: HTML response
    """
    if binding == BINDING_HTTP_REDIRECT:
        # XXX This URL extraction code is untested in practice, but it appears
        # the should be HTTP headers in http_args['headers']
        urls = [v for (k, v) in http_args['headers'] if k == 'Location']
        logger.debug('Binding {!r} redirecting to {!r}'.format(binding, urls))
        if 'url' in http_args:
            del http_args['headers']  # less debug log below
            logger.debug('XXX there is also a "url" in http_args :\n{!s}'.format(pprint.pformat(http_args)))
            if not urls:
                urls = [http_args.get('url')]
        return redirect(urls)

    # Parse the parts of http_args we know how to parse, and then warn about any remains.
    message = http_args.pop('data')
    status = http_args.pop('status', '200 Ok')
    headers = http_args.pop('headers', [])
    headers_lc = [x[0].lower() for x in headers]
    if 'content-type' not in headers_lc:
        _content_type = http_args.pop('content', 'text/html')
        headers.append(('Content-Type', _content_type))

    if http_args != {}:
        logger.debug('Unknown HTTP args when creating {!r} response :\n{!s}'.format(status, pprint.pformat(http_args)))

    if not isinstance(message, bytes):
        message = bytes(message, 'utf-8')

    return message


def geturl(query=True, path=True):
    """Rebuilds a request URL (from PEP 333).

    :param query: Is QUERY_STRING included in URI (default: True)
    :param path: Is path included in URI (default: True)
    """
    if not query:
        if not path:
            return request.host_url
        return request.base_url
    return request.url


def get_post(logger) -> Dict[str, Any]:
    """
    Return the parsed query string equivalent from a HTML POST request.

    When the method is POST the query string will be sent in the HTTP request body.

    :param logger: A logger object

    :return: query string

    :type logger: logging.Logger
    :rtype: dict
    """
    return _sanitise_items(request.form, logger)


def _sanitise_items(data: Mapping, logger: logging.Logger) -> Dict[str, str]:
    res = dict()
    san = Sanitizer()
    for k, v in data.items():
        try:
            safe_k = san.sanitize_input(k, logger=logger, content_type='text/plain')
            if safe_k != k:
                raise BadRequest()
            safe_v = san.sanitize_input(v, logger=logger, content_type='text/plain')
        except SanitationProblem as sp:
            logger.info(f'There was a problem sanitizing inputs: {repr(sp)}')
            raise BadRequest()
        res[str(safe_k)] = str(safe_v)
    return res


def get_request_header() -> Mapping[str, Any]:
    """
    Return the HTML request headers..

    :return: headers
    """
    return request.headers


def get_request_body() -> str:
    """
    Return the request body from a HTML POST request.

    :return: raw body
    """
    return request.data.decode('utf-8')


# ----------------------------------------------------------------------------
# Cookie handling
# ----------------------------------------------------------------------------
def read_cookie(name: str, logger: Logger) -> Optional[str]:
    """
    Read a browser cookie.

    :param logger: logging logger
    :returns: string with cookie content, or None
    :rtype: string | None
    """
    cookies = request.cookies
    logger.debug('Reading cookie(s): {}'.format(cookies))
    cookie = cookies.get(name)
    if not cookie:
        logger.debug(f'No {name} cookie')
        return None
    return cookie


def delete_cookie(name: str, response: FlaskResponse, current_app: 'IdPApp') -> FlaskResponse:
    """
    Ask browser to delete a cookie.

    :param name: cookie name as string
    :param logger: logging instance
    :param config: IdPConfig instance
    """
    current_app.logger.debug("Delete cookie: {!s}".format(name))
    return set_cookie(name, '/', '', response, current_app)


def set_cookie(name: str, path: str, value: str, response: FlaskResponse, current_app: 'IdPApp') -> FlaskResponse:
    """
    Ask browser to store a cookie.

    Since eduID.se is HTTPS only, the cookie parameter `Secure' is set.

    :param name: Cookie identifier (string)
    :param path: The path specification for the cookie
    :param logger: logging instance
    :param config: IdPConfig instance
    :param value: The value to assign to the cookie
    """
    response.set_cookie(
        key=name,
        value=value,
        domain=current_app.config.session_cookie_domain,
        path=path,
        secure=current_app.config.session_cookie_secure,
        httponly=current_app.config.session_cookie_httponly,
        samesite=current_app.config.session_cookie_samesite,
        max_age=current_app.config.permanent_session_lifetime,
    )
    current_app.logger.debug(f'Set cookie {repr(name)} : {repr(value)}')
    return response


def parse_query_string(logger) -> Dict[str, str]:
    """
    Parse HTML request query string into a dict like

    {'Accept': string,
     'Host': string,
    }

    NOTE: Only the first header value for each header is included in the result.

    :param logger: A logger object

    :return: parsed query string
    """
    args = _sanitise_items(request.args, logger)
    res = {}
    for k, v in args.items():
        if isinstance(v, list):
            res[k] = v[0]
        else:
            res[k] = v
    return res


def get_default_template_arguments(config):
    """
    :param config: IdP config
    :type config: OldIdPConfig
    :return: header links
    :rtype: dict
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


def get_http_method() -> str:
    """
    Get the HTTP method verb for this request.

    This function keeps other modules from having to know that CherryPy is used.

    :return: 'GET', 'POST' or other
    """
    return request.method


def get_remote_ip() -> str:
    """
    Get the remote IP address for this request.

    This function keeps other modules from having to know that CherryPy is used.

    :return: Client IP address
    :rtype: string
    """
    return request.remote_addr
