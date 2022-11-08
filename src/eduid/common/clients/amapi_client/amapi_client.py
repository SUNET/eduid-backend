from eduid.common.clients import GNAPClient
from eduid.common.clients.gnap_client.base import GNAPClientAuthData

__author__ = "masv"


class AMAPIClient(GNAPClient):
    def __init__(self, amapi_url: str, app, auth_data=GNAPClientAuthData, **kwargs):
        super().__init__(auth_data=auth_data, app=app, **kwargs)
        self.amapi_url = amapi_url
