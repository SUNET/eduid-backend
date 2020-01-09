# -*- coding: utf-8 -*-

from __future__ import absolute_import

from typing import cast, Optional, Dict

from flask import current_app, Flask

from eduid_common.authn.utils import get_saml2_config, no_authn_views
from eduid_common.api.app import get_app_config
from eduid_common.api import am, msg
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_userdb.proofing.db import EidasProofingUserDB
from eduid_userdb.logs.db import ProofingLog
from eduid_webapp.eidas.settings.common import EidasConfig

__author__ = 'lundberg'


class EidasApp(AuthnBaseApp):

    def __init__(self, name, config, *args, **kwargs):

        # Load acs actions on app init
        from . import acs_actions

        Flask.__init__(self, name, **kwargs)

        final_config = get_app_config(name, config)
        filtered_config = EidasConfig.filter_config(final_config)
        self.config = EidasConfig(**filtered_config)

        super(EidasApp, self).__init__(name, *args, **kwargs)
        self.config: EidasConfig = cast(EidasConfig, self.config)

        self.saml2_config = get_saml2_config(self.config.saml2_settings_module)
        self.config.saml2_config = self.saml2_config

        # Register views
        from eduid_webapp.eidas.views import eidas_views
        self.register_blueprint(eidas_views)

        # Register view path that should not be authorized
        self = no_authn_views(self, ['/saml2-metadata', '/saml2-acs', '/mfa-authentication'])

        # Init dbs
        self.private_userdb = EidasProofingUserDB(self.config.mongo_uri)
        self.proofing_log = ProofingLog(self.config.mongo_uri)

        # Init celery
        self = am.init_relay(self, 'eduid_eidas')
        self = msg.init_relay(self)


def init_eidas_app(name: str, config: Optional[Dict] = None):
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :return: the flask app
    :rtype: flask.Flask
    """
    app = EidasApp(name, config)

    app.logger.info(f'{name} initialized')

    return app
