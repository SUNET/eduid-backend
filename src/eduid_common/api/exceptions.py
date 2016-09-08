# -*- coding: utf-8 -*-

from flask import jsonify

__author__ = 'lundberg'


class ApiException(Exception):
    status_code = 500

    def __init__(self, flux_type='FAIL', message='ApiException', status_code=None, payload=None):
        """
        :param flux_type: Flux type
        :param message: Error message
        :param status_code: Http status code
        :param payload: Data in dict structure

        :type flux_type: str|unicode
        :type message: str|unicode
        :type status_code: int
        :type payload: dict
        """
        Exception.__init__(self)
        self.flux_type = flux_type
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def __repr__(self):
        return u'ApiException {!s} (message={!s}, status_code={!s}, payload={!r})'.format(self.flux_type, self.message,
                                                                                          self.status_code,
                                                                                          self.payload)

    def __unicode__(self):
        return self.__str__()

    def __str__(self):
        if self.payload:
            return u'{!s} {!s} with message {!s} and payload {!r}'.format(self.status_code, self.flux_type,
                                                                          self.message, self.payload)
        return u'{!s} {!s} with message {!s}'.format(self.status_code, self.flux_type, self.message)

    def to_dict(self):
        rv = dict()
        rv['type'] = self.flux_type
        rv['error'] = True
        rv['payload'] = dict(self.payload or ())
        rv['payload']['message'] = self.message
        return rv


class BadConfiguration(Exception):

    def __init__(self, message):
        Exception.__init__(self)
        self.value = message

    def __str__(self):
        return self.value


def init_exception_handlers(app):

    # Init error handler for raised exceptions
    @app.errorhandler(ApiException)
    def handle_flask_exception(error):
        app.logger.error('ApiException {!s}'.format(error))
        response = jsonify(error.to_dict())
        response.status_code = error.status_code
        return response

    # Init exception handler for input validation when webargs is used
    try:
        from webargs.flaskparser import parser as webargs_flaskparser
    except ImportError:
        pass
    else:
        @webargs_flaskparser.error_handler
        def handle_webargs_exception(error):
            app.logger.error('ApiException {!s}'.format(error))
            # TODO: Get endpoint that raised exception
            raise ApiException(message='Unprocessable Entity', status_code=error.status_code, payload=error.messages)

    return app


def init_sentry(app):
    if app.config.get('SENTRY_DSN'):
        try:
            from raven.contrib.flask import Sentry
            app = Sentry(app)
        except ImportError:
            app.logger.warning('SENTRY_DSN found but Raven not installed.')
            pass
    return app
