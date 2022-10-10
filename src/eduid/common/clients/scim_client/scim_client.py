# -*- coding: utf-8 -*-

from eduid.common.clients.gnap_client import GNAPClient
from eduid.common.clients.gnap_client.base import GNAPClientAuthData

__author__ = "lundberg"

from eduid.common.utils import urlappend


class SCIMClient(GNAPClient):
    def __init__(self, scim_server_url: str, gnap_client_auth_data=GNAPClientAuthData, **kwargs):
        super().__init__(gnap_client_auth_data=gnap_client_auth_data, **kwargs)
        self.scim_server_url = scim_server_url

    @property
    def user_endpoint(self) -> str:
        return urlappend(self.scim_server_url, "Users")

    @property
    def invite_endpoint(self) -> str:
        return urlappend(self.scim_server_url, "Invites")
