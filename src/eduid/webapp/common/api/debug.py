import pprint
import re
import sys
from collections.abc import Callable, Iterable
from typing import Any, cast
from urllib import parse
from wsgiref.types import StartResponse, WSGIEnvironment

from flask import Flask, url_for

from eduid.common.config.base import EduIDBaseAppConfig

__author__ = "lundberg"

# Configuration keys that hold credentials, and some look-alikes that do not (URLs, labels and handles)
_SECRET_KEY_RE = re.compile(
    r"secret|passw(or)?d|(^|_)pw$|(^|_)pin$|jwk|private_key|api_?key|sms_key|key_handles|backdoor_code|magic_cookie$"
    r"|(^|_)token$",
    re.IGNORECASE,
)
_NOT_SECRET_SUFFIXES = ("_url", "_link", "_label", "_handle")
_REDACTED = "REDACTED"  # same placeholder as elsewhere in the code base


def _mask_uri_password(value: str) -> str:
    """Mask the password in a URI such as mongodb://user:password@host/db."""
    scheme, separator, rest = value.partition("://")
    authority, slash, path = rest.partition("/")
    userinfo, at_sign, host = authority.rpartition("@")
    user, colon, _password = userinfo.partition(":")
    if not (separator and at_sign and colon):
        return value
    return f"{scheme}://{user}:{_REDACTED}@{host}{slash}{path}"


def _redact(key: str, value: object) -> object:
    """Hide credentials in a configuration value before it is printed."""
    is_container = isinstance(value, dict | list | tuple)
    if (isinstance(value, str | bytes) or is_container) and value:
        if _SECRET_KEY_RE.search(key) and not key.lower().endswith(_NOT_SECRET_SUFFIXES):
            return _REDACTED
        if isinstance(value, dict):
            return {k: _redact(str(k), v) for k, v in value.items()}
        if isinstance(value, list | tuple):
            return [_redact(key, v) for v in value]
        if isinstance(value, str):
            return _mask_uri_password(value)
    return value


class LoggingMiddleware:
    def __init__(self, app: Callable[..., Any]) -> None:
        self._app = app

    def __call__(self, environ: WSGIEnvironment, start_response: StartResponse) -> Iterable[bytes]:
        errorlog = environ["wsgi.errors"]
        pprint.pprint(("REQUEST", environ), stream=errorlog)

        def log_response(status: str, headers: list[tuple[str, str]], *args: Any) -> Callable[[bytes], object]:
            pprint.pprint(("RESPONSE", status, headers), stream=errorlog)
            return start_response(status, headers, *args)

        return cast(Iterable[bytes], self._app(environ, log_response))


def log_endpoints(app: Flask) -> None:
    output: list[str] = []
    with app.app_context():
        for rule in app.url_map.iter_rules():
            options: dict[str, Any] = {}
            for arg in rule.arguments:
                options[arg] = f"[{arg}]"

            methods = ",".join(rule.methods) if rule.methods else ""
            url = url_for(rule.endpoint, **options)
            line = parse.unquote(f"{rule.endpoint:50s} {methods:20s} {url}")
            output.append(line)

        for line in sorted(output):
            pprint.pprint(("ENDPOINT", line), stream=sys.stderr)


def dump_config(app: Flask, conf: EduIDBaseAppConfig) -> None:
    pprint.pprint(("CONFIGURATION", "app.config"), stream=sys.stderr)
    for key, value in sorted(app.config.items()):
        pprint.pprint((key, _redact(key, value)), stream=sys.stderr)
    pprint.pprint(("CONFIGURATION", "app.conf"), stream=sys.stderr)
    for key, value in sorted(conf.model_dump().items()):
        pprint.pprint((key, _redact(key, value)), stream=sys.stderr)


def init_app_debug(app: Flask, conf: EduIDBaseAppConfig) -> Flask:
    app.wsgi_app = LoggingMiddleware(app.wsgi_app)  # type: ignore[method-assign]
    dump_config(app, conf)
    log_endpoints(app)
    pprint.pprint(("view_functions", app.view_functions), stream=sys.stderr)
    pprint.pprint(("url_map", app.url_map), stream=sys.stderr)

    return app
