from flask import render_template
from werkzeug.exceptions import HTTPException

from eduid_webapp.idp.app import current_idp_app as current_app


def init_exception_handlers(app):

    # Init error handler for raised exceptions
    @app.errorhandler(HTTPException)
    def _handle_flask_http_exception(error):
        app.logger.error(f'IdP HTTPException {error}')
        response = error.get_response()

        context = {'error_code': error.code}

        messages = {
            'SAML_UNKNOWN_SP': 'SAML error: Unknown Service Provider',
        }

        if error.description in messages:
            context['error_details'] = '<p>' + messages[error.description] + '</p>'

        template = _get_error_template(error.code, error.description)
        current_app.logger.debug(f'Rendering {template} with context {context}')

        response.data = render_template(template, **context)

        if 'USER_TERMINATED' in error.description:
            # Delete the SSO session cookie in the browser
            response.delete_cookie(
                key='idpauthn',
                path=current_app.config.session_cookie_path,
                domain=current_app.config.session_cookie_domain
            )

        return response


def _get_error_template(status_code: int, message: str) -> str:
    pages = {
        400: 'bad_request.jinja2',
        401: 'unauthorized.jinja2',
        403: 'forbidden.jinja2',
        404: 'not_found.jinja2',
        429: 'toomany.jinja2',
        440: 'session_timeout.jinja2',
    }
    res = pages.get(status_code)
    if status_code == 403:
        if 'CREDENTIAL_EXPIRED' in message:
            res = 'credential_expired.jinja2'
        elif 'SWAMID_MFA_REQUIRED' in message:
            res = 'swamid_mfa_required.jinja2'
        elif 'MFA_REQUIRED' in message:
            res = 'mfa_required.jinja2'
        elif 'USER_TERMINATED' in message:
            res = 'user_terminated.jinja2'
    if res is None:
        res = 'error.jinja2'

    return res
