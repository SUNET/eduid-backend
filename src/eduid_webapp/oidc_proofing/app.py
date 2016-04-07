# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Flask
from oic.oic import Client
from oic.oic.message import ProviderConfigurationResponse, RegistrationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from eduid_common.api.app import eduid_init_app
from eduid_userdb.proofing import OidcProofingStateDB


__author__ = 'lundberg'


def init_oidc_client(app):
    provider_config = ProviderConfigurationResponse(**app.config['PROVIDER_CONFIGURATION_INFO'])
    oidc_client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
    oidc_client.store_registration_info(RegistrationRequest(**app.config['CLIENT_REGISTRATION_INFO']))
    oidc_client.handle_provider_config(provider_config, provider_config['issuer'])
    return oidc_client


def oidc_proofing_init_app(name, config):
    """
    Create an instance of an oidc proofing app.

    First, it will load the configuration from oidc_proofing.settings.common then any settings
    given in the `config` param.

    Then, the app instance will be updated with common stuff by `eduid_init_app`,
    and finally all needed blueprints will be registered with it.

    :param name: The name of the instance, it will affect the configuration loaded.
    :type name: str
    :param config: any additional configuration settings. Specially useful
                   in test cases
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """

    app = eduid_init_app(name, config, app_class=Flask)
    app.config.update(config)

    from eduid_webapp.oidc_proofing.views import oidc_proofing_views
    app.register_blueprint(oidc_proofing_views)

    # Initialize the oidc_client after views to be able to set correct redirect_uris
    app.oidc_client = init_oidc_client(app)

    # Initialize db
    app.proofing_statedb = OidcProofingStateDB(app.config['MONGO_URI'])

    return app

