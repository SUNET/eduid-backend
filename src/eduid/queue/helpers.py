import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import babel
from babel.support import Translations
from jinja2 import Environment, FileSystemLoader, select_autoescape
from typing_extensions import Self

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class Jinja2Env:
    """
    Initiates Jinja2 environment with Babel translations
    """

    def __init__(self):
        templates_dir = Path(__file__).with_name("templates")
        translations_dir = Path(__file__).with_name("translations")
        # Templates
        template_loader = FileSystemLoader(searchpath=templates_dir)
        logger.info(f"Loaded templates from {templates_dir}: {template_loader.list_templates()}")
        self.jinja2_env = Environment(
            loader=template_loader,
            extensions=["jinja2.ext.i18n"],
            autoescape=select_autoescape(),
        )
        # Translations
        self.translations = {
            "en": Translations.load(translations_dir, ["en"]),
            "sv": Translations.load(translations_dir, ["sv"]),
        }
        self.gettext = self.translations["en"].gettext  # default language for gettext
        logger.info(f"Loaded translations from {translations_dir}: {self.translations}")
        logger.info("Jinja2 environment loaded")

    @contextmanager
    def select_language(self, lang: str) -> Iterator[Self]:
        """
        Usage:
        with Jinja2Env().select_language(lang) as env:
            txt = env.get_template('template.jinja2').render(*args, **kwargs)
        """
        neg_lang = babel.negotiate_locale(preferred=[lang], available=self.translations.keys())
        if neg_lang:
            translation = self.translations.get(neg_lang, self.translations["en"])
        else:
            translation = self.translations["en"]
        # install_gettext_translations is available when instantiating env with extension jinja2.ext.i18n
        assert hasattr(self.jinja2_env, "install_gettext_translations")  # please mypy
        self.jinja2_env.install_gettext_translations(translation, newstyle=True)  # install gettext _ for templates
        self.gettext = translation.gettext
        yield self
