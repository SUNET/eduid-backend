# -*- coding: utf-8 -*-

from flask import request
from flask_babel import Babel

__author__ = 'lundberg'


def init_babel(app):
    babel = Babel(app)
    app.babel = babel

    @babel.localeselector
    def get_locale():
        # if a user is logged in, use the locale from the user settings
        # XXX: TODO
        # otherwise try to guess the language from the user accept
        # header the browser transmits. The best match wins.
        return request.accept_languages.best_match(app.config.get('SUPPORTED_LANGUAGES'))

    return app
