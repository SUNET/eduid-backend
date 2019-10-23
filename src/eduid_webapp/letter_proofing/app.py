# -*- coding: utf-8 -*-

from __future__ import absolute_import

from typing import cast

from flask import current_app

from eduid_common.api.app import eduid_init_app
from eduid_common.api import am, msg
from eduid_common.authn.middleware import AuthnApp
from eduid_userdb.proofing import LetterProofingStateDB, LetterProofingUserDB
from eduid_userdb.logs import ProofingLog
from eduid_webapp.letter_proofing.settings.common import LetterProofingConfig
from eduid_webapp.letter_proofing.ekopost import Ekopost

__author__ = 'lundberg'


class LetterProofingApp(AuthnApp):

    def __init__(self, *args, **kwargs):
        super(LetterProofingApp, self).__init__(*args, **kwargs)
        self.config: LetterProofingConfig = cast(LetterProofingConfig, self.config)


current_letterp_app: LetterProofingApp = cast(LetterProofingApp, current_app)


def init_letter_proofing_app(name, config=None):
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :type name: str
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """

    app = eduid_init_app(name, config,
                         config_class=LetterProofingConfig,
                         app_class=LetterProofingApp)

    # Register views
    from eduid_webapp.letter_proofing.views import letter_proofing_views
    app.register_blueprint(letter_proofing_views)

    # Init dbs
    app.private_userdb = LetterProofingUserDB(app.config.mongo_uri)
    app.proofing_statedb = LetterProofingStateDB(app.config.mongo_uri)
    app.proofing_log = ProofingLog(app.config.mongo_uri)

    # Init celery
    app = msg.init_relay(app)
    app = am.init_relay(app, 'eduid_letter_proofing')

    # Initiate external modules
    app.ekopost = Ekopost(app)

    app.logger.info('{!s} initialized'.format(name))
    return app
