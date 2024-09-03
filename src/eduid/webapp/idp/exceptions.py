from typing import TYPE_CHECKING, Optional

from flask import render_template, request
from werkzeug.exceptions import HTTPException
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.idp.mischttp import get_default_template_arguments

if TYPE_CHECKING:
    from app import IdPApp


def init_exception_handlers(app: "IdPApp") -> "IdPApp":
    def _handle_flask_http_exception(error: HTTPException) -> WerkzeugResponse:
        app.logger.error(f"IdP HTTPException {request}: {error}")
        app.logger.debug(f"Exception handler invoked on request from {request.remote_addr}: {request}")
        if app.debug or app.testing:
            app.logger.exception("Got exception in IdP")
        # It looks to me like this function get_response() returns a WerkzeugResponse, but it's
        # declared to return a sans io Response (which doesn't have a body). Don't know why.
        response: WerkzeugResponse = error.get_response()  # type: ignore[assignment]

        context = get_default_template_arguments(app.conf)
        context["error_code"] = str(error.code)

        messages = {
            "SAML_UNKNOWN_SP": "SAML error: Unknown Service Provider",
            "WRONG_USER": "Already logged in as another user - please re-initiate login",
        }

        if error.description in messages:
            context["error_details"] = "<p>" + messages[error.description] + "</p>"

        template = _get_error_template(error.code, error.description)
        app.logger.debug(f"Rendering {template} with context {context}")

        response.data = render_template(template, **context)

        if error.description in ["USER_TERMINATED", "WRONG_USER"]:
            app.logger.debug(f"Deleting SSO cookie on error {error.description}")
            # Delete the SSO session cookie in the browser
            response.delete_cookie(
                key=app.conf.sso_cookie.key,
                path=app.conf.sso_cookie.path,
                domain=app.conf.sso_cookie.domain,
            )

        return response

    # Init error handler for raised exceptions
    app.register_error_handler(HTTPException, _handle_flask_http_exception)

    return app


def _get_error_template(status_code: Optional[int], message: Optional[str]) -> str:
    pages = {
        400: "bad_request.jinja2",
        401: "unauthorized.jinja2",
        403: "forbidden.jinja2",
        404: "not_found.jinja2",
        429: "toomany.jinja2",
        440: "session_timeout.jinja2",
    }
    res = None
    if status_code is not None:
        res = pages.get(status_code)
    if status_code == 403 and message is not None:
        if "CREDENTIAL_EXPIRED" in message:
            res = "credential_expired.jinja2"
        elif "SWAMID_MFA_REQUIRED" in message:
            res = "swamid_mfa_required.jinja2"
        elif "MFA_REQUIRED" in message:
            res = "mfa_required.jinja2"
        elif "USER_TERMINATED" in message:
            res = "user_terminated.jinja2"
    if res is None:
        res = "error.jinja2"

    return res
