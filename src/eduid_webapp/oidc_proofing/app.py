# -*- coding: utf-8 -*-

from __future__ import absolute_import

from typing import cast

from flask import current_app

from eduid_common.api.app import eduid_init_app
from eduid_common.api import am, msg, mail_relay, translation, oidc
from eduid_common.authn.utils import no_authn_views
from eduid_common.authn.middleware import AuthnApp
from eduid_userdb.proofing import OidcProofingStateDB, OidcProofingUserDB
from eduid_userdb.logs import ProofingLog
from eduid_webapp.oidc_proofing.settings.common import OIDCProofingConfig

__author__ = 'lundberg'


class OIDCProofingApp(AuthnApp):

    def __init__(self, *args, **kwargs):
        super(OIDCProofingApp, self).__init__(*args, **kwargs)
        self.config: OIDCProofingConfig = cast(OIDCProofingConfig, self.config)


current_oidcp_app: OIDCProofingApp = cast(OIDCProofingApp, current_app)


def init_oidc_proofing_app(name, config):
    """
    Create an instance of an oidc proofing app.

    First, it will load the configuration from oidc_proofing.settings.common then any settings
    given in the `config` param.

    Then, the app instance will be updated with common stuff by `eduid_init_app`,
    and finally all needed blueprints will be registered with it.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :type name: str
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """

    app = eduid_init_app(name, config,
                         config_class=OIDCProofingConfig,
                         app_class=OIDCProofingApp)

    from eduid_webapp.oidc_proofing.views import oidc_proofing_views
    app.register_blueprint(oidc_proofing_views)

    # Register view path that should not be authorized
    app = no_authn_views(app, ['/authorization-response'])

    # Initialize the oidc_client after views to be able to set correct redirect_uris
    app = oidc.init_client(app)

    # Init celery
    app = msg.init_relay(app)
    app = am.init_relay(app, 'eduid_oidc_proofing')
    app = mail_relay.init_relay(app)

    # Init babel
    app = translation.init_babel(app)

    # Initialize db
    app.private_userdb = OidcProofingUserDB(app.config.mongo_uri)
    app.proofing_statedb = OidcProofingStateDB(app.config.mongo_uri)
    app.proofing_log = ProofingLog(app.config.mongo_uri)

    return app
