# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import request

from eduid_common.api.app import EduIDBaseApp
from flask_babel import Babel

__author__ = 'lundberg'


def init_babel(app: EduIDBaseApp) -> None:
    """
    :param app: Flask app
    """
    app.babel = Babel(app)
    app.logger.info('Translation directories: {}'.format([path for path in app.babel.translation_directories]))
    app.logger.info('Available translations: {}'.format(app.babel.list_translations()))

    @app.babel.localeselector
    def get_locale():
        # if a user is logged in, use the locale from the user settings
        # XXX: TODO
        # otherwise try to guess the language from the user accept
        # header the browser transmits. The best match wins.
        return request.accept_languages.best_match(app.config.get('SUPPORTED_LANGUAGES'))

    return None
