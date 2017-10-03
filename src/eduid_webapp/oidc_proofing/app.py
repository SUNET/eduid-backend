# -*- coding: utf-8 -*-

from __future__ import absolute_import

from time import sleep
from sys import exit
from requests.exceptions import ConnectionError
from oic.oic import Client
from oic.oic.message import RegistrationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from eduid_common.api.app import eduid_init_app
from eduid_common.api import am, msg
from eduid_common.authn.utils import no_authn_views
from eduid_userdb.proofing import OidcProofingStateDB, OidcProofingUserDB
from eduid_userdb.logs import ProofingLog

__author__ = 'lundberg'


def init_oidc_client(app):
    oidc_client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
    oidc_client.store_registration_info(RegistrationRequest(**app.config['CLIENT_REGISTRATION_INFO']))
    provider = app.config['PROVIDER_CONFIGURATION_INFO']['issuer']

    try:
        oidc_client.provider_config(provider)
    except ConnectionError:
        app.logger.warning('No connection to provider {!s}. Can not start without provider configuration.'
                           ' Retrying...'.format(provider))
        # Retry after 20 seconds
        sleep(20)  # Hack until we use new frontends
        try:
            oidc_client.provider_config(provider)
        except ConnectionError:
            app.logger.critical('No connection to provider {!s}. Can not start without provider configuration.'
                                ' Exiting.'.format(provider))
            exit(1)
    return oidc_client


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

    app = eduid_init_app(name, config)
    app.config.update(config)

    from eduid_webapp.oidc_proofing.views import oidc_proofing_views
    app.register_blueprint(oidc_proofing_views, url_prefix=app.config.get('APPLICATION_ROOT', None))

    # Register view path that should not be authorized
    app = no_authn_views(app, ['/authorization-response'])

    # Initialize the oidc_client after views to be able to set correct redirect_uris
    app.oidc_client = init_oidc_client(app)

    # Init celery
    app = msg.init_relay(app)
    app = am.init_relay(app, 'eduid_oidc_proofing')

    # Initialize db
    app.private_userdb = OidcProofingUserDB(app.config['MONGO_URI'])
    app.proofing_statedb = OidcProofingStateDB(app.config['MONGO_URI'])
    app.proofing_log = ProofingLog(app.config['MONGO_URI'])

    return app

