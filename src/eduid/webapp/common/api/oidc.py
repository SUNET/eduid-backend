import logging
from collections.abc import Mapping
from sys import exit
from time import sleep
from typing import Any

from oic.oic import Client
from oic.oic.message import RegistrationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from requests.exceptions import ConnectionError

__author__ = "lundberg"

logger = logging.getLogger(__name__)


def init_client(client_registration_info: Mapping[str, Any], provider_configuration_info: Mapping[str, Any]) -> Client:
    oidc_client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
    oidc_client.store_registration_info(RegistrationRequest(**client_registration_info))
    provider = provider_configuration_info["issuer"]
    try:
        oidc_client.provider_config(provider)
    except ConnectionError:
        logger.warning(
            f"No connection to provider {provider}. Can not start without provider configuration. Retrying..."
        )
        # Retry after 20 seconds so we don't get an excessive exit-restart loop
        sleep(20)
        try:
            oidc_client.provider_config(provider)
        except ConnectionError:
            logger.critical(
                f"No connection to provider {provider}. Can not start without provider configuration. Exiting."
            )
            exit(1)
    return oidc_client
