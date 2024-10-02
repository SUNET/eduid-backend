import logging
from typing import Any

import httpx

from eduid.common.clients.gnap_client.base import GNAPBearerTokenMixin, GNAPClientAuthData
from eduid.common.models.gnap_models import GrantResponse

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class AsyncGNAPClient(httpx.AsyncClient, GNAPBearerTokenMixin):
    def __init__(self, auth_data: GNAPClientAuthData, **kwargs: Any) -> None:
        if "event_hooks" not in kwargs:
            kwargs["event_hooks"] = {"response": [self.raise_on_4xx_5xx], "request": [self._add_authz_header]}

        super().__init__(**kwargs)

        self.verify = kwargs.get("verify", True)
        self._auth_data = auth_data

    @staticmethod
    async def raise_on_4xx_5xx(response: httpx.Response) -> None:
        response.raise_for_status()

    async def _request_bearer_token(self) -> GrantResponse:
        """
        Request a bearer token from the transaction endpoint.
        :return: The bearer token
        """
        data = self._create_grant_request_jws()
        async with httpx.AsyncClient(verify=self.verify) as client:
            resp = await client.post(
                url=self.transaction_uri,
                content=data,
                headers={"Content-Type": "application/jose+json"},
            )
            resp.raise_for_status()
            return GrantResponse.parse_raw(resp.text)

    async def _add_authz_header(self, request: httpx.Request) -> None:
        if not self._has_bearer_token():
            grant_response = await self._request_bearer_token()
            self._set_bearer_token(grant_response=grant_response)

        request.headers["Authorization"] = f"Bearer {self._bearer_token}"
