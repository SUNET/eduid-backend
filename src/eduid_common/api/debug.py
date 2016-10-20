# -*- coding: utf-8 -*-

import pprint

__author__ = 'lundberg'


class LoggingMiddleware(object):
    def __init__(self, app):
        self._app = app

    def __call__(self, environ, resp):
        errorlog = environ['wsgi.errors']
        pprint.pprint(('REQUEST', environ), stream=errorlog)

        def log_response(status, headers, *args):
            pprint.pprint(('RESPONSE', status, headers), stream=errorlog)
            return resp(status, headers, *args)

        return self._app(environ, log_response)


def init_app_debug(app):
    app.wsgi_app = LoggingMiddleware(app.wsgi_app)
    return app
