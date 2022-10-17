# -*- coding: utf-8 -*-
import logging
from typing import Union
from uuid import UUID

import httpx

from eduid.common.clients.gnap_client import GNAPClient
from eduid.common.clients.gnap_client.base import GNAPClientAuthData
from eduid.common.models.scim_base import BaseCreateRequest, BaseUpdateRequest, WeakVersion
from eduid.common.models.scim_invite import InviteCreateRequest, InviteResponse, InviteUpdateRequest
from eduid.common.models.scim_user import UserCreateRequest, UserResponse, UserUpdateRequest
from eduid.common.utils import urlappend

logger = logging.getLogger(__name__)

__author__ = "lundberg"


class SCIMError(Exception):
    pass


class SCIMClient(GNAPClient):
    def __init__(self, scim_server_url: str, auth_data=GNAPClientAuthData, **kwargs):
        super().__init__(auth_data=auth_data, **kwargs)
        self.event_hooks["request"].append(self._add_accept_header)
        self.scim_server_url = scim_server_url

    @staticmethod
    def raise_on_4xx_5xx(response: httpx.Response) -> None:
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            response.read()
            if "detail" in response.json():
                raise SCIMError(f"HTTP Error {response.status_code}: {response.json()['detail']}")
            raise exc

    @staticmethod
    def _add_accept_header(request: httpx.Request) -> None:
        request.headers["Accept"] = "application/scim+json"

    @staticmethod
    def _set_version_header(headers: httpx.Headers, version: WeakVersion) -> httpx.Headers:
        headers["If-Match"] = f'W/"{version}"'
        return headers

    @property
    def user_endpoint(self) -> str:
        return urlappend(self.scim_server_url, "Users")

    @property
    def invite_endpoint(self) -> str:
        return urlappend(self.scim_server_url, "Invites")

    def _get(self, endpoint: str, obj_id: Union[UUID, str]) -> httpx.Response:
        if isinstance(obj_id, UUID):
            obj_id = str(obj_id)
        return self.get(urlappend(endpoint, obj_id))

    def _create(self, endpoint: str, create_request: BaseCreateRequest) -> httpx.Response:
        return self.post(endpoint, content=create_request.json())

    def _update(self, endpoint: str, update_request: BaseUpdateRequest, version: WeakVersion) -> httpx.Response:
        headers = self._set_version_header(httpx.Headers(), version)
        return self.put(urlappend(endpoint, str(update_request.id)), content=update_request.json(), headers=headers)

    def get_user(self, user_id: Union[UUID, str]) -> UserResponse:
        ret = self._get(self.user_endpoint, obj_id=user_id)
        return UserResponse.parse_raw(ret.text)

    def create_user(self, user: UserCreateRequest) -> UserResponse:
        ret = self._create(self.user_endpoint, create_request=user)
        return UserResponse.parse_raw(ret.text)

    def update_user(self, user: UserUpdateRequest, version: WeakVersion) -> UserResponse:
        ret = self._update(self.user_endpoint, update_request=user, version=version)
        return UserResponse.parse_raw(ret.text)

    def get_invite(self, invite_id: Union[UUID, str]) -> InviteResponse:
        ret = self._get(self.invite_endpoint, obj_id=invite_id)
        return InviteResponse.parse_raw(ret.text)

    def create_invite(self, invite: InviteCreateRequest) -> InviteResponse:
        ret = self._create(self.invite_endpoint, create_request=invite)
        return InviteResponse.parse_raw(ret.text)

    def update_invite(self, invite: InviteUpdateRequest, version: WeakVersion) -> InviteResponse:
        ret = self._update(self.invite_endpoint, update_request=invite, version=version)
        return InviteResponse.parse_raw(ret.text)
