# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Flask
from requests.exceptions import ConnectionError
from oic.oic import Client
from oic.oic.message import RegistrationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from eduid_common.api.app import eduid_init_app
from eduid_userdb.proofing import OidcProofingStateDB
from eduid_webapp.oidc_proofing.mock_proof import ProofDB

# TODO: Move to base app
from webargs.flaskparser import parser as webargs_flaskparser
from eduid_common.api.exceptions import ApiException
from flask import jsonify

__author__ = 'lundberg'


def init_oidc_client(app):
    oidc_client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
    oidc_client.store_registration_info(RegistrationRequest(**app.config['CLIENT_REGISTRATION_INFO']))
    provider = app.config['PROVIDER_CONFIGURATION_INFO']['issuer']
    try:
        oidc_client.provider_config(provider)
    except ConnectionError as e:
        app.logger.critical('No connection to provider {!s}. Can not start without provider configuration.'.format(
            provider))
        raise e
    return oidc_client


def oidc_proofing_init_app(name, config):
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

    app = eduid_init_app(name, config, app_class=Flask)
    app.config.update(config)

    from eduid_webapp.oidc_proofing.views import oidc_proofing_views
    app.register_blueprint(oidc_proofing_views)

    # Initialize the oidc_client after views to be able to set correct redirect_uris
    app.oidc_client = init_oidc_client(app)

    # Initialize db
    app.proofing_statedb = OidcProofingStateDB(app.config['MONGO_URI'])
    app.proofdb = ProofDB(app.config['MONGO_URI'])

    # TODO: Move to base app
    @webargs_flaskparser.error_handler
    def handle_webargs_exception(error):
        app.logger.error('ApiException {!r}'.format(error))
        raise (ApiException(error.messages, error.status_code))

    # TODO: Move to base app
    @app.errorhandler(ApiException)
    def handle_flask_exception(error):
        app.logger.error('ApiException {!r}'.format(error))
        response = jsonify(error.to_dict())
        response.status_code = error.status_code
        return response

    return app

