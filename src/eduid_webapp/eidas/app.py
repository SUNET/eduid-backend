# -*- coding: utf-8 -*-

from __future__ import absolute_import

from typing import cast, Optional, Dict

from eduid_common.authn.utils import get_saml2_config, no_authn_views
from eduid_common.api.app import eduid_init_app
from eduid_common.api import am, msg
from eduid_common.authn.middleware import AuthnApp
from eduid_userdb.proofing.db import EidasProofingUserDB
from eduid_userdb.logs.db import ProofingLog
from eduid_webapp.eidas.settings.common import EidasConfig

__author__ = 'lundberg'


class EidasApp(AuthnApp):

    def __init__(self, *args, **kwargs):
        super(EidasApp, self).__init__(*args, **kwargs)
        self.config: EidasConfig = cast(EidasConfig, self.config)


def init_eidas_app(name: str, config: Optional[Dict] = None):
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :return: the flask app
    :rtype: flask.Flask
    """
    # Load acs actions on app init
    from . import acs_actions

    app = eduid_init_app(name, config,
                         config_class=EidasConfig,
                         app_class=EidasApp)

    app.saml2_config = get_saml2_config(app.config.saml2_settings_module)
    app.config.saml2_config = app.saml2_config

    # Register views
    from eduid_webapp.eidas.views import eidas_views
    app.register_blueprint(eidas_views)

    # Register view path that should not be authorized
    app = no_authn_views(app, ['/saml2-metadata', '/saml2-acs', '/mfa-authentication'])

    # Init dbs
    app.private_userdb = EidasProofingUserDB(app.config.mongo_uri)
    app.proofing_log = ProofingLog(app.config.mongo_uri)

    # Init celery
    app = am.init_relay(app, 'eduid_eidas')
    app = msg.init_relay(app)

    app.logger.info('{!s} initialized'.format(name))
    return app
