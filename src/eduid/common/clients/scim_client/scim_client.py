import logging
from typing import Any
from uuid import UUID

import httpx

from eduid.common.clients.gnap_client import GNAPClient
from eduid.common.clients.gnap_client.base import GNAPClientAuthData
from eduid.common.models.scim_base import BaseCreateRequest, BaseUpdateRequest, ListResponse, SearchRequest, WeakVersion
from eduid.common.models.scim_invite import InviteCreateRequest, InviteResponse, InviteUpdateRequest
from eduid.common.models.scim_user import UserCreateRequest, UserResponse, UserUpdateRequest
from eduid.common.utils import urlappend

logger = logging.getLogger(__name__)

__author__ = "lundberg"


class SCIMError(Exception):
    pass


class SCIMClient(GNAPClient):
    def __init__(self, scim_api_url: str, auth_data: GNAPClientAuthData, **kwargs: Any) -> None:
        super().__init__(auth_data=auth_data, **kwargs)
        self.event_hooks["request"].append(self._add_accept_header)
        self.scim_api_url = scim_api_url

    @staticmethod
    def raise_on_4xx_5xx(response: httpx.Response) -> None:
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            response.read()
            try:
                if "detail" in response.json():
                    raise SCIMError(f"HTTP Error {response.status_code}: {response.json()['detail']}")
            except (ValueError, TypeError):
                pass  # not json
            raise exc

    @staticmethod
    def _add_accept_header(request: httpx.Request) -> None:
        request.headers["Accept"] = "application/scim+json"

    @staticmethod
    def _set_version_header(headers: httpx.Headers, version: WeakVersion) -> httpx.Headers:
        headers["If-Match"] = f'W/"{version}"'
        return headers

    @property
    def users_endpoint(self) -> str:
        return urlappend(self.scim_api_url, "Users")

    @property
    def invites_endpoint(self) -> str:
        return urlappend(self.scim_api_url, "Invites")

    def _get(self, endpoint: str, obj_id: UUID | str) -> httpx.Response:
        if isinstance(obj_id, UUID):
            obj_id = str(obj_id)
        return self.get(urlappend(endpoint, obj_id))

    def _create(self, endpoint: str, create_request: BaseCreateRequest) -> httpx.Response:
        return self.post(endpoint, content=create_request.model_dump_json())

    def _update(self, endpoint: str, update_request: BaseUpdateRequest, version: WeakVersion) -> httpx.Response:
        headers = self._set_version_header(httpx.Headers(), version)
        return self.put(
            urlappend(endpoint, str(update_request.id)), content=update_request.model_dump_json(), headers=headers
        )

    def _search(self, endpoint: str, _filter: str, start_index: int = 1, count: int = 100) -> ListResponse:
        search_endpoint = urlappend(endpoint, ".search")
        search_req = SearchRequest(filter=_filter, start_index=start_index, count=count)
        ret = self.post(search_endpoint, content=search_req.model_dump_json())
        return ListResponse.model_validate_json(ret.text)

    def get_user(self, user_id: UUID | str) -> UserResponse:
        ret = self._get(self.users_endpoint, obj_id=user_id)
        return UserResponse.model_validate_json(ret.text)

    def create_user(self, user: UserCreateRequest) -> UserResponse:
        ret = self._create(self.users_endpoint, create_request=user)
        return UserResponse.model_validate_json(ret.text)

    def update_user(self, user: UserUpdateRequest, version: WeakVersion) -> UserResponse:
        ret = self._update(self.users_endpoint, update_request=user, version=version)
        return UserResponse.model_validate_json(ret.text)

    def get_user_by_external_id(self, external_id: str | None) -> UserResponse | None:
        if external_id is None:
            return None

        _filter = f'externalId eq "{external_id}"'
        ret = self._search(self.users_endpoint, _filter=_filter)
        if ret.total_results == 0:
            return None
        if ret.total_results > 1:
            raise SCIMError(f'More than one user with external_id "{external_id}"')
        return self.get_user(user_id=ret.resources[0]["id"])

    def get_invite(self, invite_id: UUID | str) -> InviteResponse:
        ret = self._get(self.invites_endpoint, obj_id=invite_id)
        return InviteResponse.model_validate_json(ret.text)

    def create_invite(self, invite: InviteCreateRequest) -> InviteResponse:
        ret = self._create(self.invites_endpoint, create_request=invite)
        return InviteResponse.model_validate_json(ret.text)

    def update_invite(self, invite: InviteUpdateRequest, version: WeakVersion) -> InviteResponse:
        ret = self._update(self.invites_endpoint, update_request=invite, version=version)
        return InviteResponse.model_validate_json(ret.text)
