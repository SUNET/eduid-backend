import logging
import re
from abc import ABCMeta
from typing import Any, Callable, List, Tuple, Union
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from flask import current_app
from werkzeug.wrappers import Response
from werkzeug.wsgi import get_current_url

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.utils import urlappend
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.utils import get_from_current_app
from eduid.webapp.common.session import session
from eduid.webapp.common.session.redis_session import NoSessionDataFoundException

no_context_logger = logging.getLogger(__name__)


THeaders = List[Tuple[str, str]]
TStartResponse = Callable[[str, THeaders], None]


class AuthnBaseApp(EduIDBaseApp, metaclass=ABCMeta):
    """
    WSGI middleware that checks whether the request is authenticated,
    and in case it isn't, redirects to the authn service.
    """

    def __call__(self, environ: dict[str, Any], start_response: TStartResponse) -> Union[Response, list[str]]:
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

        url_parts = list(urlparse(ts_url))
        query = parse_qs(url_parts[4])
        query.update(params)

        url_parts[4] = urlencode(query)
        location = urlunparse(url_parts)

        headers = [("Location", location)]
        start_response("302 Found", headers)
        return []
