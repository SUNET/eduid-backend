# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import current_app, Flask

from eduid_common.api import am, msg
from eduid_common.api.app import get_app_config
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_userdb.logs import ProofingLog
from eduid_userdb.proofing import LetterProofingStateDB, LetterProofingUserDB
from eduid_webapp.letter_proofing.ekopost import Ekopost
from eduid_webapp.letter_proofing.settings.common import LetterProofingConfig

__author__ = 'lundberg'


class LetterProofingApp(AuthnBaseApp):

    def __init__(self, name, config, *args, **kwargs):

        Flask.__init__(self, name, **kwargs)

        # Init app config
        final_config = get_app_config(name, config)
        filtered_config = LetterProofingConfig.filter_config(final_config)
        self.config = LetterProofingConfig(**filtered_config)

        super(LetterProofingApp, self).__init__(name, *args, **kwargs)

        # Register views
        from eduid_webapp.letter_proofing.views import letter_proofing_views
        self.register_blueprint(letter_proofing_views)

        # Init dbs
        self.private_userdb = LetterProofingUserDB(self.config.mongo_uri)
        self.proofing_statedb = LetterProofingStateDB(self.config.mongo_uri)
        self.proofing_log = ProofingLog(self.config.mongo_uri)
        # Init celery
        msg.init_relay(self)
        am.init_relay(self, 'eduid_letter_proofing')
        # Initiate external modules
        self.ekopost = Ekopost(self)


def get_current_app() -> LetterProofingApp:
    """Teach pycharm about app"""
    return current_app  # type: ignore


current_letterp_app = get_current_app()


def init_letter_proofing_app(name, config=None) -> LetterProofingApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :return: the flask app
    """
    app = LetterProofingApp(name, config)

    app.logger.info(f'Init {name} app...')

    return app
