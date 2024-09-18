# This SAML IdP implementation is derived from the pysaml2 example 'idp2'.
# That code is covered by the following copyright (from pysaml2 LICENSE.txt 2013-05-06) :
#
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright notice, this list of
#       conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright notice, this list
#       of conditions and the following disclaimer in the documentation and/or other materials
#       provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY ROLAND HEDBERG ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ROLAND HEDBERG OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# -------------------------------------------------------------------------------
#
# All the changes made during the eduID development are subject to the following
# copyright:
#
# Copyright (c) 2013 SUNET. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY SUNET "AS IS" AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL SUNET OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of SUNET.

"""
Miscellaneous HTTP related functions.
"""

from __future__ import annotations

import logging
import pprint
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import user_agents
from bleach import clean
from flask import make_response, redirect, request
from saml2 import BINDING_HTTP_REDIRECT
from typing_extensions import Self
from user_agents.parsers import UserAgent
from werkzeug.exceptions import BadRequest, InternalServerError
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.config.base import CookieConfig
from eduid.webapp.common.api.sanitation import SanitationProblem, Sanitizer
from eduid.webapp.idp.settings.common import IdPConfig

logger = logging.getLogger(__name__)


@dataclass
class HttpArgs:
    """Dataclass to remove the ambiguities of pysaml2:s apply_binding() return value"""

    method: str
    url: str
    headers: Sequence[tuple[str, str]]
    body: str | None

    @classmethod
    def from_pysaml2_dict(cls: type[Self], http_args: dict[str, Any]) -> Self:
        # Parse the parts of http_args we know how to parse, and then warn about any remains.
        if "status" in http_args and http_args["status"] != 200:
            logger.warning(f'Ignoring status in http_args: {http_args["status"]}')
        method = http_args.pop("method")
        url = http_args.pop("url")
        message = http_args.pop("data")
        status = http_args.pop("status", "200 Ok")
        headers = http_args.pop("headers", [])
        headers_lc = [x[0].lower() for x in headers]
        if "content-type" not in headers_lc:
            _content_type = http_args.pop("content", "text/html")
            headers.append(("Content-Type", _content_type))

        if http_args != {}:
            logger.debug(f"Unknown HTTP args when creating {repr(status)} response :\n{pprint.pformat(http_args)}")

        return cls(method=method, url=url, headers=headers, body=message)

    @property
    def redirect_url(self) -> str | None:
        """
        Get the destination URL for a redirect.

        Use the header Location first, and secondly 'url' from http_args.
        """
        for k, v in self.headers:
            if k.lower() == "location":
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
        if http_args.method != "GET":
            logger.warning(f"BINDING_HTTP_REDIRECT method is not GET ({http_args.method})")
        location = http_args.redirect_url
        logger.debug(f"Binding {binding} redirecting to {repr(location)}")
        if not location:
            raise InternalServerError("No redirect destination")
        if http_args.url:
            if not location.startswith(http_args.url):
                logger.warning(f'There is another "url" in args: {http_args.url} (location: {location})')
        return redirect(location)

    message = b""
    if isinstance(http_args.body, bytes):
        message = http_args.body
    elif http_args.body is not None:
        message = bytes(http_args.body, "utf-8")

    response = make_response(message)
    for k, v in http_args.headers:
        _old_v = response.headers.get(k)
        if v != _old_v:
            logger.debug(f"Changing response header {repr(k)} from {repr(_old_v)} -> {repr(v)}")
            response.headers[k] = v
    return response


def get_post() -> dict[str, Any]:
    """
    Return the parsed query string equivalent from a HTML POST request.

    When the method is POST the query string will be sent in the HTTP request body.

    :return: query string
    """
    return _sanitise_items(request.form)


def _sanitise_items(data: Mapping[str, Any]) -> dict[str, str]:
    res = dict()
    san = Sanitizer()
    for k, v in data.items():
        try:
            safe_k = san.sanitize_input(k, content_type="text/plain")
            if safe_k != k:
                raise BadRequest()
            safe_v = san.sanitize_input(v, content_type="text/plain")
        except SanitationProblem:
            logger.exception("There was a problem sanitizing inputs")
            raise BadRequest()
        res[str(safe_k)] = str(safe_v)
    return res


# ----------------------------------------------------------------------------
# Cookie handling
# ----------------------------------------------------------------------------
def read_cookie(name: str) -> str | None:
    """
    Read a browser cookie.

    :returns: string with cookie content, or None
    """
    cookies = request.cookies
    logger.debug(f"Reading cookie(s): {cookies}")
    cookie = cookies.get(name)
    if not cookie:
        logger.debug(f"No IdP SSO cookie ({name}) found")
        return None
    return cookie


def set_sso_cookie(sso_cookie: CookieConfig, value: str, response: WerkzeugResponse) -> WerkzeugResponse:
    """
    Ask the browser to store an SSO cookie.

    :param value: The value to assign to the cookie
    :param response: Flask response object
    """
    response.set_cookie(
        key=sso_cookie.key,
        value=value,
        domain=sso_cookie.domain,
        path=sso_cookie.path,
        secure=sso_cookie.secure,
        httponly=sso_cookie.httponly,
        samesite=sso_cookie.samesite,
        max_age=sso_cookie.max_age_seconds,
    )
    _cookie = response.headers.get("Set-Cookie")
    logger.debug(f"Set SSO cookie {_cookie}")
    return response


def parse_query_string() -> dict[str, str]:
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


def get_default_template_arguments(config: IdPConfig) -> dict[str, str]:
    """
    :return: header links
    """
    return {
        "dashboard_link": config.dashboard_link,
        "signup_link": config.signup_link,
        "student_link": config.student_link,
        "technicians_link": config.technicians_link,
        "staff_link": config.staff_link,
        "faq_link": config.faq_link,
        "password_reset_link": config.password_reset_link,
        "static_link": config.static_link,
    }


@dataclass
class IdPUserAgent:
    parsed: UserAgent
    safe_str: str


def get_user_agent() -> IdPUserAgent | None:
    """Get the request User-Agent and parse it in a safe and controlled way"""
    user_agent = request.headers.get("user-agent")
    if not user_agent:
        return None

    safe_str = clean(user_agent[:200])
    parsed = user_agents.parse(safe_str)

    return IdPUserAgent(parsed=parsed, safe_str=safe_str)
