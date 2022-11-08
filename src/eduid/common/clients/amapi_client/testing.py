from typing import Optional

import respx
from httpx import Response

from eduid.common.clients.gnap_client.testing import MockedSyncAuthAPIMixin


class MockedAMAPIMixin(MockedSyncAuthAPIMixin):
    def start_mock_amapi(self, access_token_value: Optional[str] = None):
        self.start_mock_auth_api(access_token_value=access_token_value)

        self.mocked_users = respx.mock(base_url="http://localhost", assert_all_called=False)
        put_users_name = self.mocked_users.put(
            url="/users/hubba-bubba/name",
            # path__regex=r".*",
            name="users_name_request",
        )
        # put_users_name.return_value = Response(418)
        put_users_name.pass_through()
        self.mocked_users.start()
        self.addCleanup(self.mocked_users.stop)  # type: ignore
        # respx.route(host="http://localhost").pass_through()
        # my_route = respx.put(url="http://localhost/users/hubba-bubba/name").pass_through()
        mura = 1


# self.mocked_scim_api = respx.mock(base_url="http://localhost/scim", assert_all_called=False)
#        get_invite_route = self.mocked_scim_api.get(
#            path__regex=r"^/Invites/[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z",
#            name="get_invite_request",
#        )
