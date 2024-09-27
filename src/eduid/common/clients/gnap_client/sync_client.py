import logging
from typing import Any

import httpx

from eduid.common.clients.gnap_client.base import GNAPBearerTokenMixin, GNAPClientAuthData
from eduid.common.models.gnap_models import GrantResponse

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class GNAPClient(httpx.Client, GNAPBearerTokenMixin):
    def __init__(self, auth_data: GNAPClientAuthData, **kwargs: Any):
        if "event_hooks" not in kwargs:
            kwargs["event_hooks"] = {"response": [self.raise_on_4xx_5xx], "request": [self._add_authz_header]}

        super().__init__(**kwargs)

        self.verify = kwargs.get("verify", True)
        self._auth_data = auth_data

    @staticmethod
    def raise_on_4xx_5xx(response: httpx.Response) -> None:
        response.raise_for_status()

    def _request_bearer_token(self) -> GrantResponse:
        """
        Request a bearer token from the transaction endpoint.
        :return: The bearer token
        """
        data = self._create_grant_request_jws()
        resp = httpx.post(
            url=self.transaction_uri,
            content=data,
            headers={"Content-Type": "application/jose+json"},
            verify=self.verify,
        )
        resp.raise_for_status()
        return GrantResponse.parse_raw(resp.text)

    def _add_authz_header(self, request: httpx.Request) -> None:
        if not self._has_bearer_token():
            grant_response = self._request_bearer_token()
            self._set_bearer_token(grant_response=grant_response)

        request.headers["Authorization"] = f"Bearer {self._bearer_token}"
