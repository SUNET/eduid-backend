import json
import logging
import re
from abc import ABCMeta
from typing import TYPE_CHECKING, Iterable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from flask import Request, current_app, jsonify, make_response
from flask_cors.core import get_cors_headers, get_cors_options
from werkzeug.wrappers import Response
from werkzeug.wsgi import get_current_url

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.utils import urlappend
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.messages import error_response
from eduid.webapp.common.api.schemas.base import FluxStandardAction
from eduid.webapp.common.session import session
from eduid.webapp.common.session.redis_session import NoSessionDataFoundException

if TYPE_CHECKING:
    from _typeshed.wsgi import StartResponse, WSGIEnvironment

no_context_logger = logging.getLogger(__name__)


class AuthnBaseApp(EduIDBaseApp, metaclass=ABCMeta):
    """
    WSGI middleware that checks whether the request is authenticated,
    and in case it isn't, redirects to the authn service.
    """

    def __call__(self, environ: "WSGIEnvironment", start_response: "StartResponse") -> Iterable[bytes]:
        # let request with method OPTIONS pass through
        if environ["REQUEST_METHOD"] == "OPTIONS":
            return super().__call__(environ, start_response)

        next_url = get_current_url(environ)
        next_path = list(urlparse(next_url))[2]
        # Since trailing slashes is 'optional' in HTTP, we remove them before matching the path
        # against the elements in the allow-list to avoid all of them having to consider that.
        while next_path.endswith("/"):
            next_path = next_path[:-1]

        conf = getattr(self, "conf", None)
        if not isinstance(conf, EduIDBaseAppConfig):
            raise RuntimeError(f"Could not find conf in {self}")

        allowlist = conf.no_authn_urls

        no_context_logger.debug(f"Checking if URL path {next_path} matches no auth allow list: {allowlist}")
        for regex in allowlist:
            m = re.match(regex, next_path)
            if m is not None:
                no_context_logger.debug(f"{next_path} matched allow list")
                return super().__call__(environ, start_response)

        with self.request_context(environ):
            try:
                if session.common.eppn and session.common.is_logged_in:
                    return super().__call__(environ, start_response)
            except NoSessionDataFoundException:
                current_app.logger.info("Caught a NoSessionDataFoundException - forcing the user to authenticate")
                del environ["HTTP_COOKIE"]  # Force relogin
                # If HTTP_COOKIE is not removed self.request_context(environ) below
                # will try to look up the Session data in the backend

            ts_url = urlappend(conf.token_service_url, "login")

            params = {"next": next_url}

            if conf.enable_authn_json_response:
                # NEW way, respond with a 401 with a JSON payload
                params["login_url"] = ts_url
                res = error_response(message="Authentication required", payload=params)
                _encoded = cast(Mapping[str, Any], FluxStandardAction().dump(res.to_dict()))
                body = json.dumps(_encoded).encode("utf-8")
                headers = [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(body))),
                    ("WWW-Authenticate", "eduID"),
                ]
                start_response("401 Unauthorized", headers)
                # return make_response(jsonify(_encoded), 401)
                return [body]

        # OLD way, respond with a 301 redirect

        url_parts = list(urlparse(ts_url))
        query = parse_qs(url_parts[4])
        # Set the 'next' query parameter. parse_qs says it returns a list of values for each key,
        # but if we add [next_url], the result will be actually "...&next=%5B...%5D" which is not what we want."
        # Don't know why that is, but url_parts[4] is probably empty (unless there are query parameters in
        # conf.token_service_url) so let's just ignore the type error for now.
        query.update(params)  # type: ignore
        url_parts[4] = urlencode(query)
        location = urlunparse(url_parts)

        # add cors headers to authentication redirect response
        req = Request(environ)
        cors_options = get_cors_options(self)
        cors_headers = get_cors_headers(
            options=cors_options,
            request_headers=req.headers,
            request_method=req.method,
        )
        # cors_headers is a MultiDict, start_response wants a list of tuples
        headers = []
        for key, value in cors_headers.items():
            headers.append((key, value))

        # Add redirect location to header
        headers.append(("Location", location))
        start_response("302 Found", headers)
        return []
