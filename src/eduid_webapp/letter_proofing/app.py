# -*- coding: utf-8 -*-

from __future__ import absolute_import

from eduid_common.api.app import eduid_init_app
from eduid_common.api import am, msg
from eduid_userdb.proofing import LetterProofingStateDB, LetterProofingUserDB
from eduid_userdb.logs import ProofingLog
from eduid_webapp.letter_proofing.ekopost import Ekopost

__author__ = 'lundberg'


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

    app = eduid_init_app(name, config)

    # Register views
    from eduid_webapp.letter_proofing.views import letter_proofing_views
    app.register_blueprint(letter_proofing_views, url_prefix=app.config.get('APPLICATION_ROOT', None))

    # Init dbs
    app.private_userdb = LetterProofingUserDB(app.config['MONGO_URI'])
    app.proofing_statedb = LetterProofingStateDB(app.config['MONGO_URI'])
    app.proofing_log = ProofingLog(app.config['MONGO_URI'])

    # Init celery
    app = msg.init_relay(app)
    app = am.init_relay(app, 'eduid_letter_proofing')

    # Initiate external modules
    app.ekopost = Ekopost(app)

    app.logger.info('{!s} initialized'.format(name))
    return app
