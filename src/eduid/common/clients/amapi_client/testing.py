from collections.abc import Iterator

import pytest
import respx

from eduid.common.clients.gnap_client.testing import MockedSyncAuthAPIMixin


class MockedAMAPIMixin(MockedSyncAuthAPIMixin):
    @pytest.fixture(autouse=True)
    def _stop_mock_amapi(self) -> Iterator[None]:
        yield
        if hasattr(self, "mocked_users"):
            self.mocked_users.stop()

    def start_mock_amapi(self, access_token_value: str | None = None) -> None:
        self.start_mock_auth_api(access_token_value=access_token_value)

        self.mocked_users = respx.mock(base_url="http://localhost", assert_all_called=False)
        put_users_name_route = self.mocked_users.put(
            url="/users/hubba-bubba/name",
            name="put_users_name_request",
        )
        put_users_name_route.pass_through()
        self.mocked_users.start()
