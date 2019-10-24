# -*- coding: utf-8 -*-

from __future__ import absolute_import

from typing import cast

from flask import current_app

from eduid_userdb.proofing import OrcidProofingStateDB, OrcidProofingUserDB
from eduid_userdb.logs import ProofingLog
from eduid_common.api.app import eduid_init_app
from eduid_common.api import am, oidc
from eduid_common.authn.middleware import AuthnApp
from eduid_common.authn.utils import no_authn_views
from eduid_common.api.debug import init_app_debug
from eduid_webapp.orcid.settings.common import OrcidConfig

__author__ = 'lundberg'


class OrcidApp(AuthnApp):

    def __init__(self, *args, **kwargs):
        super(OrcidApp, self).__init__(*args, **kwargs)
        self.config: OrcidConfig = cast(OrcidConfig, self.config)


current_orcid_app: OrcidApp = cast(OrcidApp, current_app)


def init_orcid_app(name, config=None):
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
                         config_class=OrcidConfig,
                         app_class=OrcidApp)

    # Register views
    from eduid_webapp.orcid.views import orcid_views
    app.register_blueprint(orcid_views)

    # Init dbs
    app.private_userdb = OrcidProofingUserDB(app.config.mongo_uri)
    app.proofing_statedb = OrcidProofingStateDB(app.config.mongo_uri)
    app.proofing_log = ProofingLog(app.config.mongo_uri)

    # Init celery
    app = am.init_relay(app, 'eduid_orcid')

    # Initialize the oidc_client
    app = oidc.init_client(app)

    app.logger.info('{!s} initialized'.format(name))
    return app
