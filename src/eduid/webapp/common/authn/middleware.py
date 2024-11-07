import json
import logging
import re
from abc import ABCMeta
from collections.abc import Iterable, Mapping
from typing import Any, cast
from urllib.parse import urlparse
from wsgiref.types import StartResponse, WSGIEnvironment

from flask import Request, current_app
from flask_cors.core import get_cors_headers, get_cors_options
from werkzeug.wsgi import get_current_url

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.messages import error_response
from eduid.webapp.common.api.schemas.base import FluxStandardAction
from eduid.webapp.common.session import session
from eduid.webapp.common.session.redis_session import NoSessionDataFoundException

no_context_logger = logging.getLogger(__name__)


class AuthnBaseApp(EduIDBaseApp, metaclass=ABCMeta):
    """
    WSGI middleware that checks whether the request is authenticated,
    and in case it isn't, redirects to the authn service.
    """

    def __call__(self, environ: WSGIEnvironment, start_response: StartResponse) -> Iterable[bytes]:
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

        res = error_response(message="Authentication required")
        _encoded = cast(Mapping[str, Any], FluxStandardAction().dump(res.to_dict()))
        body = json.dumps(_encoded).encode("utf-8")
        headers = [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
            ("WWW-Authenticate", "eduID"),
        ]
        headers = self._add_cors_headers(environ=environ, headers=headers)
        start_response("401 Unauthorized", headers)
        return [body]

    def _add_cors_headers(
        self, environ: "WSGIEnvironment", headers: list[tuple[str, str]] | None = None
    ) -> list[tuple[str, str]]:
        if headers is None:
            headers = []
        # add cors headers to authentication redirect response
        req = Request(environ)
        cors_options = get_cors_options(self)
        cors_headers = get_cors_headers(
            options=cors_options,
            request_headers=req.headers,
            request_method=req.method,
        )
        # cors_headers is a MultiDict, start_response wants a list of tuples
        for key, value in cors_headers.items():
            headers.append((key, value))
        return headers
