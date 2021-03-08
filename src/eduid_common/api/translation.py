# -*- coding: utf-8 -*-

import pkg_resources
from flask import request
from flask_babel import Babel

from eduid_common.api.app import EduIDBaseApp
from eduid_common.session import session

__author__ = 'lundberg'


def init_babel(app: EduIDBaseApp) -> None:
    """
    :param app: Flask app
    """
    conf_translations_dirs = app.config.get('BABEL_TRANSLATION_DIRECTORIES', '')
    # Add pkg_resource path to translation directory as the default location does not work
    pkg_translations_dir = pkg_resources.resource_filename('eduid_webapp', 'translations')
    app.config['BABEL_TRANSLATION_DIRECTORIES'] = f'{conf_translations_dirs};{pkg_translations_dir}'
    app.babel = Babel(app)
    app.logger.info('Translation directories: {}'.format([path for path in app.babel.translation_directories]))
    app.logger.info('Available translations: {}'.format(app.babel.list_translations()))

    @app.babel.localeselector
    def get_locale():
        # if a user is logged in, use the locale from the user settings
        if session.common.preferred_language is not None:
            lang = session.common.preferred_language
            app.logger.debug(f'Language in session: {lang}')
            return lang
        # otherwise try to guess the language from the user accept
        # header the browser transmits. The best match wins.
        lang = request.accept_languages.best_match(app.conf.available_languages)
        app.logger.debug(f'Language (best match) for request: {lang}')
        return lang

    return None
