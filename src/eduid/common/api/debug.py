# -*- coding: utf-8 -*-
import pprint
import sys
import warnings
from dataclasses import asdict
from urllib import parse

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
            line = parse.unquote("{:50s} {:20s} {}".format(rule.endpoint, methods, url))
            output.append(line)

        for line in sorted(output):
            pprint.pprint(('ENDPOINT', line), stream=sys.stderr)


def dump_config(app):
    pprint.pprint(('CONFIGURATION', 'app.config'), stream=sys.stderr)
    try:
        config_items = asdict(app.config).items()
    except TypeError:
        config_items = app.config.items()
        warnings.warn(f'{app.name} is using old dict config', DeprecationWarning)
    for key, value in sorted(config_items):
        pprint.pprint((key, value), stream=sys.stderr)


def init_app_debug(app):
    app.wsgi_app = LoggingMiddleware(app.wsgi_app)
    dump_config(app)
    log_endpoints(app)
    pprint.pprint(('view_functions', app.view_functions), stream=sys.stderr)
    pprint.pprint(('url_map', app.url_map), stream=sys.stderr)

    return app
