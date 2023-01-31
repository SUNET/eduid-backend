from typing import Mapping, Optional

import respx
from httpx import Response, Request
from eduid.common.models.amapi_user import UserUpdateNameRequest

from eduid.common.clients.gnap_client.testing import MockedSyncAuthAPIMixin
from eduid.userdb.userdb import AmDB


class MockedAMAPIMixin(MockedSyncAuthAPIMixin):
    def start_mock_amapi(self, central_user_db: Optional[AmDB] = None, access_token_value: Optional[str] = None):
        self.start_mock_auth_api(access_token_value=access_token_value)
        self.central_user_db = central_user_db
        self.mocked_users = respx.mock(base_url="http://localhost/amapi", assert_all_called=False)
        put_users_name_route = self.mocked_users.put(
            url="/users/hubba-bubba/name",
            name="put_users_name_request",
        )
        put_users_name_route.mock(side_effect=self._save)
        self.mocked_users.start()
        self.addCleanup(self.mocked_users.stop)  # type: ignore

    def _save(self, request: Request) -> Response:
        if self.central_user_db is None:
            raise ValueError("save user side affect was called but self.amdb is None")
        mock_request = UserUpdateNameRequest.parse_raw(request.content)

        db_user = self.central_user_db.get_user_by_eppn("hubba-bubba")
        db_user.given_name = mock_request.given_name
        db_user.surname = mock_request.surname
        db_user.display_name = mock_request.display_name
        self.central_user_db.save(user=db_user)
        return Response(200, text='{"status": "true"}')
