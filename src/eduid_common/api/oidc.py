# -*- coding: utf-8 -*-

from sys import exit
from time import sleep

from requests.exceptions import ConnectionError

from oic.oic import Client
from oic.oic.message import RegistrationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

__author__ = 'lundberg'


def init_client(app):
    oidc_client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
    oidc_client.store_registration_info(RegistrationRequest(**app.config['CLIENT_REGISTRATION_INFO']))
    provider = app.config['PROVIDER_CONFIGURATION_INFO']['issuer']
    try:
        oidc_client.provider_config(provider)
    except ConnectionError:
        app.logger.warning(
            'No connection to provider {!s}. Can not start without provider configuration.'
            ' Retrying...'.format(provider)
        )
        # Retry after 20 seconds so we don't get an excessive exit-restart loop
        sleep(20)
        try:
            oidc_client.provider_config(provider)
        except ConnectionError:
            app.logger.critical(
                'No connection to provider {!s}. Can not start without provider configuration.'
                ' Exiting.'.format(provider)
            )
            exit(1)
    app.oidc_client = oidc_client
    return app
