from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from flask import Flask, Response, jsonify
from werkzeug.exceptions import HTTPException

__author__ = "lundberg"

if TYPE_CHECKING:
    from eduid.userdb.reset_password import ResetPasswordEmailState


class ApiException(Exception):
    status_code = 500

    def __init__(
        self,
        message: str = "ApiException",
        status_code: int | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> None:
        """
        :param message: Error message
        :param status_code: Http status code
        :param payload: Data in dict structure
        """
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def __repr__(self) -> str:
        return f"ApiException (message={self.message!s}, status_code={self.status_code!s}, payload={self.payload!r})"

    def __unicode__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        if self.payload:
            return f"{self.status_code!s} with message {self.message!s} and payload {self.payload!r}"
        return f"{self.status_code!s} with message {self.message!s}"

    def to_dict(self) -> dict[str, Any]:
        rv: dict[str, Any] = dict()
        rv["message"] = self.message
        if self.payload:
            rv["payload"] = self.payload
        return rv


class EduidTooManyRequests(Exception):
    pass


class EduidForbidden(Exception):
    pass


class VCCSBackendFailure(Exception):
    pass


class ProofingLogFailure(Exception):
    pass


class ThrottledException(Exception):
    state: "ResetPasswordEmailState"

    def __init__(self, state: "ResetPasswordEmailState") -> None:
        Exception.__init__(self)
        self.state = state


def init_exception_handlers(app: Flask) -> Flask:
    # Init error handler for raised exceptions
    @app.errorhandler(400)
    def _handle_flask_http_exception(error: HTTPException) -> Response:
        app.logger.error(f"HttpException {error!s}")
        e = ApiException(error.name, error.code)
        if app.config.get("DEBUG"):
            e.payload = {"description": error.description}
        response = jsonify(e.to_dict())
        response.status_code = e.status_code
        return response

    return app


def init_sentry(app: Flask) -> Flask:
    if app.config.get("SENTRY_DSN"):
        try:
            from raven.contrib.flask import Sentry

            sentry = Sentry(dsn=app.config.get("SENTRY_DSN"))
            sentry.init_app(app)
        except ImportError:
            app.logger.warning("SENTRY_DSN found but Raven not installed.")
    return app
