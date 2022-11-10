# -*- coding: utf-8 -*-

import respx
from httpx import Response

from eduid.common.models.gnap_models import AccessTokenResponse, GrantResponse

__author__ = "lundberg"


class MockedSyncAuthAPIMixin:
    def start_mock_auth_api(self):
        self.mocked_auth_api = respx.mock(base_url="http://localhost/auth", assert_all_called=False)
        transaction_route = self.mocked_auth_api.post("/transaction", name="transaction_request")
        grant_response = GrantResponse(access_token=AccessTokenResponse(value="test_jwt"))
        transaction_route.return_value = Response(200, text=grant_response.json(exclude_none=True))
        self.mocked_auth_api.start()
        self.addCleanup(self.mocked_auth_api.stop)  # type: ignore