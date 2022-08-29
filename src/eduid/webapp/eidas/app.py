# -*- coding: utf-8 -*-


from typing import Any, Mapping, Optional, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.common.rpc.msg_relay import MsgRelay
from eduid.userdb.logs.db import ProofingLog
from eduid.userdb.proofing.db import EidasProofingUserDB
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.common.authn.utils import get_saml2_config, no_authn_views
from eduid.webapp.eidas.settings.common import EidasConfig

__author__ = 'lundberg'


class EidasApp(AuthnBaseApp):
    def __init__(self, config: EidasConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.conf = config

        self.saml2_config = get_saml2_config(config.saml2_settings_module)

        # Init dbs
        self.private_userdb = EidasProofingUserDB(config.mongo_uri)
        self.proofing_log = ProofingLog(config.mongo_uri)

        # Init celery
        self.am_relay = AmRelay(config)
        self.msg_relay = MsgRelay(config)


current_eidas_app: EidasApp = cast(EidasApp, current_app)


def init_eidas_app(name: str = 'eidas', test_config: Optional[Mapping[str, Any]] = None) -> EidasApp:
    """
    Create an instance of an eidas app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """
    config = load_config(typ=EidasConfig, app_name=name, ns='webapp', test_config=test_config)

    # Load acs actions on app init
    from . import acs_actions

    # Make sure pycharm doesn't think the import above is unused and removes it
    if acs_actions.__author__:
        pass

    app = EidasApp(config)

    app.logger.info(f'Init {app}...')

    # Register views
    from eduid.webapp.eidas.old_views import old_eidas_views
    from eduid.webapp.eidas.views import eidas_views

    app.register_blueprint(eidas_views)
    app.register_blueprint(old_eidas_views)

    # Register view path that should not be authorized
    no_authn_views(config, ['/saml2-metadata', '/saml2-acs', '/mfa-authentication', '/mfa-authenticate'])

    return app
