# -*- coding: utf-8 -*-

from flask import current_app, jsonify

__author__ = 'lundberg'


class ApiException(Exception):
    status_code = 500

    def __init__(self, message='ApiException', status_code=None, payload=None):
        """
        :param message: Error message
        :param status_code: Http status code
        :param payload: Data in dict structure

        :type message: str|unicode
        :type status_code: int
        :type payload: dict
        """
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def __repr__(self):
        return u'ApiException (message={!s}, status_code={!s}, payload={!r})'.format(
            self.message, self.status_code, self.payload
        )

    def __unicode__(self):
        return self.__str__()

    def __str__(self):
        if self.payload:
            return u'{!s} with message {!s} and payload {!r}'.format(self.status_code, self.message, self.payload)
        return u'{!s} with message {!s}'.format(self.status_code, self.message)

    def to_dict(self):
        rv = dict()
        rv['message'] = self.message
        if self.payload:
            rv['payload'] = self.payload
        return rv


class TaskFailed(Exception):
    pass


class AmTaskFailed(TaskFailed):
    pass


class MsgTaskFailed(TaskFailed):
    pass


class MailTaskFailed(TaskFailed):
    pass


class EduidTooManyRequests(Exception):
    pass


class EduidForbidden(Exception):
    pass


def init_exception_handlers(app):

    # Init error handler for raised exceptions
    @app.errorhandler(400)
    def _handle_flask_http_exception(error):
        app.logger.error('HttpException {!s}'.format(error))
        e = ApiException(error.name, error.code)
        if current_app.config.get('DEBUG', False):
            e.payload = {'description': error.description}
        response = jsonify(e.to_dict())
        response.status_code = e.status_code
        return response

    return app


def init_sentry(app):
    if app.config.get('SENTRY_DSN'):
        try:
            from raven.contrib.flask import Sentry

            sentry = Sentry(dsn=app.config.get('SENTRY_DSN'))
            sentry.init_app(app)
        except ImportError:
            app.logger.warning('SENTRY_DSN found but Raven not installed.')
            pass
    return app
