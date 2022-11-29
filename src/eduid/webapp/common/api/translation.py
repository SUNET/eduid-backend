# -*- coding: utf-8 -*-
from typing import Optional

import pkg_resources
from flask import request
from flask_babel import Babel
from eduid.common.config.base import EduIDBaseAppConfig

from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.session import session

__author__ = "lundberg"


def init_babel(app: EduIDBaseApp) -> Babel:
    """
    :param app: Flask app
    """
    _conf = getattr(app, "conf")
    assert isinstance(_conf, EduIDBaseAppConfig)
    conf_translations_dirs = _conf.flask.babel_translation_directories
    # Add pkg_resource path to translation directory as the default location does not work
    pkg_translations_dir = pkg_resources.resource_filename("eduid.webapp", "translations")
    app.config["BABEL_TRANSLATION_DIRECTORIES"] = f"{conf_translations_dirs};{pkg_translations_dir}"
    babel = Babel(app)
    app.logger.info("Translation directories: {}".format([path for path in babel.translation_directories]))
    app.logger.info("Available translations: {}".format(babel.list_translations()))

    @babel.localeselector
    def get_locale() -> Optional[str]:
        lang: Optional[str]  # mypy 0.910 needs this
        # if a user is logged in, use the locale from the user settings
        if session.common.preferred_language is not None:
            lang = session.common.preferred_language
            app.logger.debug(f"Language in session: {lang}")
            return lang
        # otherwise try to guess the language from the user accept
        # header the browser transmits. The best match wins.
        _conf = getattr(app, "conf")
        assert isinstance(_conf, EduIDBaseAppConfig)
        lang = request.accept_languages.best_match(_conf.available_languages)
        app.logger.debug(f"Language (best match) for request: {lang}")
        return lang

    return babel
