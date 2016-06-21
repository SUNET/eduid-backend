# -*- coding: utf-8 -*-

from __future__ import absolute_import

from eduid_common.api.app import eduid_init_app
from eduid_userdb.proofing import LetterProofingStateDB
from eduid_webapp.letter_proofing.ekopost import Ekopost
from eduid_webapp.letter_proofing.msg import init_celery

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
    from eduid_webapp.letter_proofing.views import idproofing_letter_views
    app.register_blueprint(idproofing_letter_views)

    # Init dbs
    app.proofing_statedb = LetterProofingStateDB(app.config['MONGO_URI'])

    # Init celery
    init_celery(app)

    # Initiate external modules
    app.ekopost = Ekopost(app)

    app.logger.info('{!s} initialized'.format(name))
    return app
