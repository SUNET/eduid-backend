from typing import Any

import httpx

from eduid.common.clients import GNAPClient
from eduid.common.clients.gnap_client.base import GNAPClientAuthData
from eduid.common.utils import urlappend

__author__ = "masv"

from eduid.common.models.amapi_user import (
    UserUpdateResponse,
    UserUpdateNameRequest,
    UserUpdateEmailRequest,
    UserUpdateLanguageRequest,
    UserUpdatePhoneRequest,
    UserUpdateTerminateRequest,
)


class AMAPIClient(GNAPClient):
    def __init__(self, amapi_url: str, app, auth_data=GNAPClientAuthData, **kwargs):
        super().__init__(auth_data=auth_data, app=app, **kwargs)
        self.amapi_url = amapi_url

    def _users_base_url(self) -> str:
        return urlappend(self.amapi_url, "users")

    def _put(self, base_path: str, user: str, endpoint: str, body: Any) -> httpx.Response:
        return self.put(urlappend(base_path, f"{user}/{endpoint}"), json=body.json())

    def update_user_email(self, user: str, body: UserUpdateEmailRequest) -> UserUpdateResponse:
        ret = self._put(base_path=self._users_base_url(), user=user, endpoint="email", body=body)
        return UserUpdateResponse.parse_raw(ret.text)

    def update_user_name(self, user: str, body: UserUpdateNameRequest) -> UserUpdateResponse:
        ret = self._put(base_path=self._users_base_url(), user=user, endpoint="name", body=body)
        return UserUpdateResponse.parse_raw(ret.text)

    def update_user_language(self, user: str, body: UserUpdateLanguageRequest) -> UserUpdateResponse:
        ret = self._put(base_path=self._users_base_url(), user=user, endpoint="language", body=body)
        return UserUpdateResponse.parse_raw(ret.text)

    def update_user_phone(self, user: str, body: UserUpdatePhoneRequest) -> UserUpdateResponse:
        ret = self._put(base_path=self._users_base_url(), user=user, endpoint="phone", body=body)
        return UserUpdateResponse.parse_raw(ret.text)

    def update_user_terminate(self, user: str, body: UserUpdateTerminateRequest) -> UserUpdateResponse:
        ret = self._put(base_path=self._users_base_url(), user=user, endpoint="terminate", body=body)
        return UserUpdateResponse.parse_raw(ret.text)
