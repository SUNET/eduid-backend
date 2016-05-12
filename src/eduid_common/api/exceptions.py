# -*- coding: utf-8 -*-

from flask import jsonify

__author__ = 'lundberg'


class ApiException(Exception):
    status_code = 500

    def __init__(self, message='ApiException', status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def __repr__(self):
        return u'ApiException(message={!s}, status_code={!s}, payload={!r})'.format(self.message, self.status_code,
                                                                                    self.payload)

    def __unicode__(self):
        return self.__str__()

    def __str__(self):
        if self.payload:
            return u'{!s} {!s} {!r}'.format(self.status_code, self.message, self.payload)
        return u'{!s} {!s}'.format(self.status_code, self.message)

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
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
            raise ApiException('Unprocessable Entity', error.status_code, error.messages)

    return app
