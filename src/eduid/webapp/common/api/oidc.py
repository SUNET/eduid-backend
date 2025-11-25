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
    oidc_client.provider_config(provider)
    return oidc_client
