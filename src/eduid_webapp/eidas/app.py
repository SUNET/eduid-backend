# -*- coding: utf-8 -*-

from __future__ import absolute_import

from typing import cast

from flask import current_app

from eduid_common.api import am, msg
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_common.authn.utils import get_saml2_config, no_authn_views
from eduid_userdb.logs.db import ProofingLog
from eduid_userdb.proofing.db import EidasProofingUserDB

from eduid_webapp.eidas.settings.common import EidasConfig

__author__ = 'lundberg'


class EidasApp(AuthnBaseApp):
    def __init__(self, name: str, config: dict, **kwargs):

        # Load acs actions on app init
        from . import acs_actions

        # Make sure pycharm doesn't think the import above is unused and removes it
        if acs_actions.__author__:
            pass

        # Initialise type of self.config before any parent class sets a precedent to mypy
        self.config = EidasConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)
        # cast self.config because sometimes mypy thinks it is a FlaskConfig after super().__init__()
        self.config: EidasConfig = cast(EidasConfig, self.config)  # type: ignore

        self.saml2_config = get_saml2_config(self.config.saml2_settings_module)

        # Register views
        from eduid_webapp.eidas.views import eidas_views

        self.register_blueprint(eidas_views)

        # Register view path that should not be authorized
        no_authn_views(self, ['/saml2-metadata', '/saml2-acs', '/mfa-authentication'])

        # Init dbs
        self.private_userdb = EidasProofingUserDB(self.config.mongo_uri)
        self.proofing_log = ProofingLog(self.config.mongo_uri)

        # Init celery
        am.init_relay(self, 'eduid_eidas')
        msg.init_relay(self)


current_eidas_app: EidasApp = cast(EidasApp, current_app)


def init_eidas_app(name: str, config: dict) -> EidasApp:
    """
    Create an instance of an eidas app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases
    """
    app = EidasApp(name, config)

    app.logger.info(f'{name} initialized')

    return app
