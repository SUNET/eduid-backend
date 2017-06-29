# -*- coding: utf-8 -*-

from __future__ import absolute_import

from eduid_common.api.app import eduid_init_app
from eduid_common.api import am, msg
from eduid_userdb.proofing import LookupMobileProofingUserDB
from eduid_userdb.logs import ProofingLog
from eduid_webapp.lookup_mobile_proofing import lookup_mobile_relay

__author__ = 'lundberg'


def init_lookup_mobile_proofing_app(name, config=None):
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
    from eduid_webapp.lookup_mobile_proofing.views import mobile_proofing_views
    app.register_blueprint(mobile_proofing_views, url_prefix=app.config.get('APPLICATION_ROOT', None))

    # Init dbs
    app.proofing_userdb = LookupMobileProofingUserDB(app.config['MONGO_URI'])
    app.proofing_log = ProofingLog(app.config['MONGO_URI'])

    # Init celery
    app = lookup_mobile_relay.init_relay(app)
    app = msg.init_relay(app)
    app = am.init_relay(app, 'eduid_lookup_mobile_proofing')

    app.logger.info('{!s} initialized'.format(name))
    return app
