import pprint
import sys
import warnings
from collections.abc import Callable, Iterable
from dataclasses import asdict
from typing import Any
from urllib import parse

from flask import Flask, url_for

# TODO: in python >= 3.11 import from wsgiref.types
from eduid.webapp.common.wsgi import StartResponse, WSGIEnvironment

__author__ = "lundberg"


class LoggingMiddleware:
    def __init__(self, app: Callable[..., Any]):
        self._app = app

    def __call__(self, environ: WSGIEnvironment, start_response: StartResponse) -> Iterable[bytes]:
        errorlog = environ["wsgi.errors"]
        pprint.pprint(("REQUEST", environ), stream=errorlog)

        def log_response(status: str, headers: list[tuple[str, str]], *args: Any):
            pprint.pprint(("RESPONSE", status, headers), stream=errorlog)
            return start_response(status, headers, *args)

        return self._app(environ, log_response)


def log_endpoints(app: Flask) -> None:
    output: list[str] = []
    with app.app_context():
        for rule in app.url_map.iter_rules():
            options = {}
            for arg in rule.arguments:
                options[arg] = f"[{arg}]"

            methods = ",".join(rule.methods) if rule.methods else ""
            url = url_for(rule.endpoint, values=options)
            line = parse.unquote(f"{rule.endpoint:50s} {methods:20s} {url}")
            output.append(line)

        for line in sorted(output):
            pprint.pprint(("ENDPOINT", line), stream=sys.stderr)


def dump_config(app: Flask) -> None:
    pprint.pprint(("CONFIGURATION", "app.config"), stream=sys.stderr)
    try:
        config_items = asdict(app.config).items()  # type: ignore[call-overload]
    except TypeError:
        config_items = app.config.items()
        warnings.warn(f"{app.name} is using old dict config", DeprecationWarning)
    for key, value in sorted(config_items):
        pprint.pprint((key, value), stream=sys.stderr)


def init_app_debug(app: Flask) -> Flask:
    app.wsgi_app = LoggingMiddleware(app.wsgi_app)  # type: ignore[method-assign]
    dump_config(app)
    log_endpoints(app)
    pprint.pprint(("view_functions", app.view_functions), stream=sys.stderr)
    pprint.pprint(("url_map", app.url_map), stream=sys.stderr)

    return app
