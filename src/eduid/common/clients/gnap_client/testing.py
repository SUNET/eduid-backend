from unittest import TestCase

import respx
from httpx import Response

from eduid.common.models.gnap_models import AccessTokenResponse, GrantResponse

__author__ = "lundberg"


class MockedSyncAuthAPIMixin(TestCase):
    mocked_auth_api: respx.MockRouter

    def start_mock_auth_api(self, access_token_value: str | None = None) -> None:
        if access_token_value is None:
            access_token_value = "mock_jwt"
        # set using="httpx" until https://github.com/lundberg/respx/issues/277 is fixed
        self.mocked_auth_api = respx.mock(base_url="http://localhost/auth", assert_all_called=False, using="httpx")
        transaction_route = self.mocked_auth_api.post("/transaction", name="transaction_request")
        grant_response = GrantResponse(access_token=AccessTokenResponse(value=access_token_value))
        transaction_route.return_value = Response(200, text=grant_response.json(exclude_none=True))
        self.mocked_auth_api.start()
        self.addCleanup(self.mocked_auth_api.stop)
