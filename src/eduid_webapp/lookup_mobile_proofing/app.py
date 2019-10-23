# -*- coding: utf-8 -*-

from __future__ import absolute_import

from typing import cast

from flask import current_app

from eduid_common.api.app import eduid_init_app
from eduid_common.api import am, msg
from eduid_common.authn.middleware import AuthnApp
from eduid_userdb.proofing import LookupMobileProofingUserDB
from eduid_userdb.logs import ProofingLog
from eduid_webapp.lookup_mobile_proofing import lookup_mobile_relay
from eduid_webapp.lookup_mobile_proofing.settings.common import MobileProofingConfig

__author__ = 'lundberg'


class MobileProofingApp(AuthnApp):

    def __init__(self, *args, **kwargs):
        super(LetterProofingApp, self).__init__(*args, **kwargs)
        self.config: LetterProofingConfig = cast(LetterProofingConfig, self.config)


current_mobilep_app: MobileProofingApp = cast(MobileProofingApp, current_app)


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

    app = eduid_init_app(name, config,
                         config_class=LetterProofingConfig,
                         app_class=LetterProofingApp)

    # Register views
    from eduid_webapp.lookup_mobile_proofing.views import mobile_proofing_views
    app.register_blueprint(mobile_proofing_views)

    # Init dbs
    app.private_userdb = LookupMobileProofingUserDB(app.config.mongo_uri)
    app.proofing_log = ProofingLog(app.config.mongo_uri)

    # Init celery
    app = lookup_mobile_relay.init_relay(app)
    app = msg.init_relay(app)
    app = am.init_relay(app, 'eduid_lookup_mobile_proofing')

    app.logger.info('{!s} initialized'.format(name))
    return app
