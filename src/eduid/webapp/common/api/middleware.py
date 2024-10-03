__author__ = "lundberg"

from collections.abc import Callable, Iterable
from typing import Any

# TODO: in python >= 3.11 import from wsgiref.types
from eduid.webapp.common.wsgi import StartResponse, WSGIEnvironment


# Copied from https://stackoverflow.com/questions/18967441/add-a-prefix-to-all-flask-routes/36033627#36033627
class PrefixMiddleware:
    def __init__(self, app: Callable[..., Any], prefix: str = "", server_name: str = "") -> None:
        self.app = app
        if prefix is None:
            prefix = ""
        if server_name is None:
            server_name = ""
        self.prefix = prefix
        self.server_name = server_name

    def __call__(self, environ: WSGIEnvironment, start_response: StartResponse) -> Iterable[bytes]:
        # Handle localhost requests for health checks
        if environ.get("REMOTE_ADDR") == "127.0.0.1":
            environ["HTTP_HOST"] = self.server_name
            environ["SCRIPT_NAME"] = self.prefix
            return self.app(environ, start_response)
        elif environ.get("PATH_INFO", "").startswith(self.prefix):
            environ["PATH_INFO"] = environ["PATH_INFO"][len(self.prefix) :]
            environ["SCRIPT_NAME"] = self.prefix
            return self.app(environ, start_response)
        else:
            start_response("404", [("Content-Type", "text/plain")])
            return [b"Not found."]
