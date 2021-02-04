# -*- coding: utf-8 -*-


from typing import Any, Mapping, Optional, cast

from flask import current_app

from eduid_common.api import am, msg
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_common.authn.utils import get_saml2_config, no_authn_views
from eduid_common.config.base import FlaskConfig
from eduid_common.config.parsers import load_config
from eduid_userdb.logs.db import ProofingLog
from eduid_userdb.proofing.db import EidasProofingUserDB

from eduid_webapp.eidas.settings.common import EidasConfig

__author__ = 'lundberg'


class EidasApp(AuthnBaseApp):
    def __init__(self, name: str, test_config: Optional[Mapping[str, Any]], **kwargs):

        # Load acs actions on app init
        from . import acs_actions

        # Make sure pycharm doesn't think the import above is unused and removes it
        if acs_actions.__author__:
            pass

        self.conf = load_config(typ=EidasConfig, app_name=name, ns='webapp', test_config=test_config)
        # Initialise type of self.config before any parent class sets a precedent to mypy
        self.config = FlaskConfig.init_config(ns='webapp', app_name=name, test_config=test_config)
        super().__init__(name, **kwargs)

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


def init_eidas_app(name: str, test_config: Optional[Mapping[str, Any]]) -> EidasApp:
    """
    Create an instance of an eidas app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    app = EidasApp(name, test_config)

    app.logger.info(f'{name} initialized')

    return app
