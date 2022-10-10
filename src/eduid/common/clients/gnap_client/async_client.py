# -*- coding: utf-8 -*-
import asyncio
import logging
from typing import Optional

import httpx
from httpx import Response, Headers
from httpx._types import HeaderTypes, URLTypes
from jwcrypto.jwk import JWK

from eduid.common.clients.gnap_client.base import GNAPBearerTokenMixin, GNAPClientAuthData
from eduid.common.misc.timeutil import utc_now
from eduid.common.models.gnap_models import GrantResponse

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class AsyncGNAPClient(httpx.AsyncClient, GNAPBearerTokenMixin):
    def __init__(self, gnap_client_auth_data: GNAPClientAuthData, **kwargs):
        super().__init__(**kwargs)
        self._auth_data = gnap_client_auth_data

    async def _request_bearer_token(self) -> None:
        """
        Request a bearer token from the transaction endpoint.
        :return: The bearer token
        """
        data = self._create_grant_request_jws()
        resp = await super().request(
            method="POST",
            url=self.transaction_uri,
            content=data,
            headers={"Content-Type": "application/jose+json"},
        )
        resp.raise_for_status()
        self._set_bearer_token(grant_response=GrantResponse.parse_raw(resp.text))

    async def request(self, method: str, url: URLTypes, headers: Optional[HeaderTypes] = None, **kwargs) -> Response:
        if not self._bearer_token or utc_now() > self._bearer_token_expires_at:
            await self._request_bearer_token()
        headers = self._add_authz_header(headers=Headers(headers))
        return await super().request(method, url, headers=headers, **kwargs)


async def main():
    cjwk = JWK(
        **{
            "kty": "EC",
            "kid": "devkey",
            "crv": "P-256",
            "x": "LsX8Jl-DwZfJjgkwvTiRu5nqMNYcwh29hdkDtCsj26w",
            "y": "hifFMvRh_moHOvBLx58JokS0LMjjo3Ww5SfjzFVSVSA",
            "d": "tghyR6Z5kmJZiEw3VBF8d5VGCSaXX_-4w8TN94auHP0",
        }
    )
    gnap_client_auth_data = GNAPClientAuthData(
        authn_server_url="https://api.eduid.docker/auth/",
        key_name="devkey",
        client_jwk=cjwk,
        access=["test", "test2"],
    )
    async with AsyncGNAPClient(
        gnap_client_auth_data=gnap_client_auth_data,
        verify=False,
    ) as client:
        ret = await client.get("https://api.eduid.docker/auth/docs")
        print(ret.request.headers)
        print(client._bearer_token)


if __name__ == "__main__":
    asyncio.run(main())
