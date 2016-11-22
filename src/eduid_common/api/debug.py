# -*- coding: utf-8 -*-

import sys
import pprint
import urllib
from flask import url_for

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


def log_endpoints(app):
    output = []
    with app.app_context():
        for rule in app.url_map.iter_rules():

            options = {}
            for arg in rule.arguments:
                options[arg] = "[{0}]".format(arg)

            methods = ','.join(rule.methods)
            url = url_for(rule.endpoint, **options)
            line = urllib.unquote("{:50s} {:20s} {}".format(rule.endpoint, methods, url))
            output.append(line)

        for line in sorted(output):
            pprint.pprint(('ENDPOINT', line), stream=sys.stderr)


def dump_config(app):
    pprint.pprint(('CONFIGURATION', app.config), stream=sys.stderr)


def init_app_debug(app):
    app.wsgi_app = LoggingMiddleware(app.wsgi_app)
    log_endpoints(app)
    dump_config(app)
    return app
