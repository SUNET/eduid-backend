import respx
from httpx import Response

from eduid.common.clients.gnap_client.testing import MockedSyncAuthAPIMixin

__author__ = "lundberg"

from eduid.common.models.scim_invite import InviteResponse
from eduid.common.models.scim_user import UserResponse


class MockedScimAPIMixin(MockedSyncAuthAPIMixin):
    mocked_scim_api: respx.MockRouter

    # TODO: Maybe find a better way to make the responses dynamic
    get_invite_response = {
        "id": "74d9c09a-55ea-4fa6-9bc1-5f8aa815ee68",
        "meta": {
            "location": "http://localhost/scim/Invites/74d9c09a-55ea-4fa6-9bc1-5f8aa815ee68",
            "last_modified": "2022-10-19T13:43:23.497000+00:00",
            "resource_type": "Invite",
            "created": "2022-10-14T09:42:15.657000+00:00",
            "version": 'W/"634ffefb3e3eb19969655036"',
        },
        "schemas": [
            "https://scim.eduid.se/schema/nutid/invite/core-v1",
            "https://scim.eduid.se/schema/nutid/invite/v1",
            "https://scim.eduid.se/schema/nutid/user/v1",
        ],
        "nutid_invite_v1": {
            "name": {"family_name": "Testsson", "given_name": "Test"},
            "emails": [{"value": "invite1@example.com", "primary": True}],
            "phone_numbers": [{"value": "tel:+46701234567", "primary": True}],
            "national_identity_number": "190102031234",
            "preferred_language": "sv",
            "groups": [],
            "inviter_name": "Test Inviter",
            "send_email": True,
            "finish_url": "https://finish.example.com",
            "completed": "2022-10-19T13:43:23.491000+00:00",
            "expires_at": "2023-04-12T09:42:15.658000+00:00",
        },
        "nutid_user_v1": {"profiles": {}, "linked_accounts": []},
    }

    post_user_response = {
        "id": "232fd0df-3223-4117-8783-5706038bc6c0",
        "meta": {
            "location": "https://scimapi.eduid.docker/scim/Users/232fd0df-3223-4117-8783-5706038bc6c0",
            "last_modified": "2022-10-14T14:52:40.195000+00:00",
            "resource_type": "User",
            "created": "2020-05-14T15:14:27.132000+00:00",
            "version": 'W/"634977b8a801fe61ab59b44f"',
        },
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "https://scim.eduid.se/schema/nutid/user/v1"],
        "external_id": "rabog-zorul@eduid.se",
        "name": {"family_name": "Testdotter", "given_name": "Testaren"},
        "emails": [],
        "phone_numbers": [],
        "groups": [
            {
                "value": "fe54dc67-ac7b-42b9-a9e9-105a9e03d72f",
                "ref": "https://scimapi.eduid.docker/scim/Groups/fe54dc67-ac7b-42b9-a9e9-105a9e03d72f",
                "display": "Test Group 1",
            },
            {
                "value": "dafd908c-377c-435a-964b-4d4967b23c55",
                "ref": "https://scimapi.eduid.docker/scim/Groups/dafd908c-377c-435a-964b-4d4967b23c55",
                "display": "Test Group 5",
            },
        ],
        "nutid_user_v1": {
            "profiles": {
                "student": {"attributes": {"displayName": "Charles And"}, "data": {"test_key": "ett nytt v\u00e4rde"}},
                "other_profile": {"attributes": {"displayName": "Kalle Anka"}, "data": {}},
            },
            "linked_accounts": [],
        },
    }

    put_user_response = post_user_response

    def start_mocked_scim_api(self) -> None:
        self.start_mock_auth_api()

        # set using="httpx" until https://github.com/lundberg/respx/issues/277 is fixed
        self.mocked_scim_api = respx.mock(base_url="http://localhost/scim", assert_all_called=False, using="httpx")
        get_invite_route = self.mocked_scim_api.get(
            path__regex=r"^/Invites/[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z",
            name="get_invite_request",
        )
        get_invite_route.return_value = Response(
            200, text=InviteResponse(**self.get_invite_response).model_dump_json(exclude_none=True)
        )
        post_user_route = self.mocked_scim_api.post("/Users", name="post_user_request")
        post_user_route.return_value = Response(
            201, text=UserResponse(**self.post_user_response).model_dump_json(exclude_none=True)
        )
        put_user_route = self.mocked_scim_api.put(
            path__regex=r"^/Users/[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z",
            name="put_user_request",
        )
        put_user_route.return_value = Response(
            200, text=UserResponse(**self.put_user_response).model_dump_json(exclude_none=True)
        )

        self.mocked_scim_api.start()
        self.addCleanup(self.mocked_scim_api.stop)
