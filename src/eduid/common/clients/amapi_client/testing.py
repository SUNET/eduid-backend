from typing import Optional

import respx
from eduid.common.clients.gnap_client.testing import MockedSyncAuthAPIMixin


class MockedAMAPIMixin(MockedSyncAuthAPIMixin):
    def start_mock_amapi(self, access_token_value: Optional[str] = None):
        self.start_mock_auth_api(access_token_value=access_token_value)

        self.mocked_users = respx.mock(base_url="http://localhost", assert_all_called=False)
        put_users_name = self.mocked_users.put(
            url="/users/hubba-bubba/name",
            name="users_name_request",
        )
        put_users_name.pass_through()
        self.mocked_users.start()
        self.addCleanup(self.mocked_users.stop)  # type: ignore
