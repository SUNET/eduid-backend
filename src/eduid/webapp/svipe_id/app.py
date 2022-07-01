# -*- coding: utf-8 -*-

from typing import Any, Mapping, Optional, cast

from flask import current_app

from eduid.common.config.parsers import load_config
from eduid.common.rpc.am_relay import AmRelay
from eduid.userdb.svipe_id.db import SvipeIdUserDB
from eduid.webapp.common.api import oidc
from eduid.webapp.common.authn.middleware import AuthnBaseApp
from eduid.webapp.svipe_id.settings.common import SvipeIdConfig

__author__ = 'lundberg'


class SvipeIdApp(AuthnBaseApp):
    def __init__(self, config: SvipeIdConfig, **kwargs):
        super().__init__(config, **kwargs)

        self.conf = config
        # Init dbs
        self.private_userdb = SvipeIdUserDB(self.conf.mongo_uri)
        # Init celery
        self.am_relay = AmRelay(config)
        # Initialize the oidc_client
        self.oidc_client = oidc.init_client(config.client_registration_info, config.provider_configuration_info)


current_svipe_id_app = cast(SvipeIdApp, current_app)


def svipe_id_init_app(name: str = 'svipe_id', test_config: Optional[Mapping[str, Any]] = None) -> SvipeIdApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config. Used in test cases.

    :return: the flask app
    """
    config = load_config(typ=SvipeIdConfig, app_name=name, ns='webapp', test_config=test_config)

    app = SvipeIdApp(config)

    app.logger.info(f'Init {app}...')

    # Register views
    from eduid.webapp.svipe_id.views import svipe_id_views

    app.register_blueprint(svipe_id_views)

    app.logger.info('{!s} initialized'.format(name))
    return app
