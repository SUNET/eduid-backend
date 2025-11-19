from importlib.resources import files

from flask import current_app, request
from flask_babel import Babel

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.session import session

__author__ = "lundberg"


def get_user_locale() -> str | None:
    app = current_app
    assert isinstance(app, EduIDBaseApp)
    lang: str | None  # mypy 0.910 needs this
    # if a user is logged in, use the locale from the user settings
    if session.common.preferred_language is not None:
        lang = session.common.preferred_language
        app.logger.debug(f"Language in session: {lang}")
        return lang
    # otherwise try to guess the language from the user accept
    # header the browser transmits. The best match wins.
    _conf = getattr(app, "conf")
    lang = request.accept_languages.best_match(_conf.available_languages)
    app.logger.debug(f"Language (best match) for request: {lang}")
    return lang


def init_babel(app: EduIDBaseApp) -> Babel:
    """
    :param app: Flask app
    """

    _conf = getattr(app, "conf")
    assert isinstance(_conf, EduIDBaseAppConfig)
    conf_translations_dirs = ";".join(_conf.flask.babel_translation_directories)
    # Add pkg_resource path to translation directory as the default location does not work
    pkg_translations_dir = str(files("eduid.webapp") / "translations")
    translations_directories = f"{conf_translations_dirs};{pkg_translations_dir}"
    app.logger.info(f"Translation directories: {[path for path in translations_directories.split(';')]}")
    app.config["BABEL_TRANSLATION_DIRECTORIES"] = translations_directories

    babel = Babel()
    babel.init_app(app=app, locale_selector=get_user_locale)
    return babel
