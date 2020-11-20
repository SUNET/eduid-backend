# -*- coding: utf-8 -*-

import logging
from contextlib import contextmanager

import babel
import pkg_resources
from babel.support import Translations
from jinja2 import Environment, FileSystemLoader, select_autoescape

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class Jinja2Env:
    """
    Initiates Jinja2 environment with Babel translations
    """

    def __init__(self):
        templates_dir = pkg_resources.resource_filename('eduid_queue', 'templates')
        translations_dir = pkg_resources.resource_filename('eduid_queue', 'translations')
        # Templates
        template_loader = FileSystemLoader(searchpath=templates_dir)
        logger.info(f'Loaded templates from {templates_dir}: {template_loader.list_templates()}')
        self.env = Environment(
            loader=template_loader,
            extensions=['jinja2.ext.i18n', 'jinja2.ext.autoescape'],
            autoescape=select_autoescape(),
        )
        # Translations
        self.translations = {
            'en': Translations.load(translations_dir, ['en']),
            'sv': Translations.load(translations_dir, ['sv']),
        }
        logger.info(f'Loaded translations from {translations_dir}: {self.translations}')
        logger.info('Jinja2 environment loaded')

    @contextmanager
    def select_language(self, lang: str):
        """
        Usage:
        with Jinja2Env().select_language(lang) as env:
            txt = env.get_template('template.jinja2').render(*args, **kwargs)
        """
        neg_lang = babel.negotiate_locale(preferred=[lang], available=self.translations.keys())
        translation = self.translations.get(neg_lang, self.translations['en'])
        # install_gettext_translations is available when instantiating env with extension jinja2.ext.i18n
        self.env.install_gettext_translations(translation, newstyle=True)
        yield self.env
