import json
from collections.abc import Mapping
from http import HTTPStatus
from typing import Any

from jwcrypto import jwt

from eduid.maccapi.testing import MAccApiTestCase


class TestMAccApi(MAccApiTestCase):
    def setUp(self) -> None:
        self.user1 = {"given_name": "Test", "surname": "User"}
        self.user2 = {"given_name": "Test", "surname": "User2"}
        self.user3 = {"given_name": "Test", "surname": "User3"}
        self.domain = "eduid.se"
        self.claims = {
            "saml_eppn": "test@eduid.se",
            "version": 1,
            "scopes": [self.domain],
            "auth_source": "config",
            "requested_access": [{"type": "maccapi", "scope": "eduid.se"}],
        }

        return super().setUp()

    def _make_bearer_token(self, claims: Mapping[str, Any]) -> str:
        token = jwt.JWT(header={"alg": "ES256"}, claims=claims)
        jwk = list(self.context.jwks)[0]
        token.make_signed_token(jwk)
        return token.serialize()

    def _is_presentable_format(self, password: str) -> bool:
        return len(password) == 14 and password[4] == " " and password[9] == " "

    def test_create_user(self) -> None:
        domain = "eduid.se"
        claims = {
            "saml_eppn": "test@eduid.se",
            "version": 1,
            "scopes": [domain],
            "auth_source": "config",
            "requested_access": [{"type": "maccapi", "scope": "eduid.se"}],
        }
        token = self._make_bearer_token(claims=claims)

        headers = self.headers
        headers["Authorization"] = f"Bearer {token}"

        response = self.client.post(url="/Users/create", json=self.user1, headers=headers)
        assert response.status_code == HTTPStatus.CREATED

        content = response.content.decode("utf-8")
        payload = json.loads(content)

        assert payload["status"] == "success"
        # production is default scope unless set to something else in config
        assert payload["scope"] == "eduid.se"
        assert payload["user"]["given_name"] == self.user1["given_name"]
        assert payload["user"]["surname"] == self.user1["surname"]
        assert payload["user"]["eppn"] is not None
        assert payload["user"]["password"] is not None

    def test_create_multiple_users(self) -> None:
        claims = {
            "saml_eppn": "test@eduid.se",
            "version": 1,
            "scopes": ["test.eduid.se"],
            "auth_source": "config",
            "requested_access": [{"type": "maccapi", "scope": "test.eduid.se"}],
        }
        token = self._make_bearer_token(claims=claims)

        headers = self.headers
        headers["Authorization"] = f"Bearer {token}"

        response = self.client.post(url="/Users/create", json=self.user1, headers=headers)
        assert response.status_code == HTTPStatus.CREATED

        # Create two users in another scope
        token = self._make_bearer_token(claims=self.claims)

        headers = self.headers
        headers["Authorization"] = f"Bearer {token}"

        response = self.client.post(url="/Users/create", json=self.user2, headers=headers)
        assert response.status_code == HTTPStatus.CREATED
        response = self.client.post(url="/Users/create", json=self.user3, headers=headers)
        assert response.status_code == HTTPStatus.CREATED
        response = self.client.get(url="/Users", headers=headers)
        assert response.status_code == HTTPStatus.OK

        content = response.content.decode("utf-8")
        payload = json.loads(content)

        assert payload["status"] == "success"
        assert len(payload["users"]) == 2

    def test_remove_user(self) -> None:
        token = self._make_bearer_token(claims=self.claims)

        headers = self.headers
        headers["Authorization"] = f"Bearer {token}"

        response = self.client.post(url="/Users/create", json=self.user1, headers=headers)
        assert response.status_code == HTTPStatus.CREATED

        content = response.content.decode("utf-8")
        payload = json.loads(content)
        eppn = payload["user"]["eppn"]

        response = self.client.post(url="/Users/remove", json={"eppn": eppn}, headers=headers)

        content = response.content.decode("utf-8")
        payload = json.loads(content)
        assert payload["status"] == "success"
        assert payload["user"]["eppn"] == eppn
        assert payload["user"]["given_name"] == self.user1["given_name"]
        assert payload["user"]["surname"] == self.user1["surname"]

    def test_reset_password(self) -> None:
        token = self._make_bearer_token(claims=self.claims)

        headers = self.headers
        headers["Authorization"] = f"Bearer {token}"

        response = self.client.post(url="/Users/create", json=self.user1, headers=headers)
        assert response.status_code == HTTPStatus.CREATED

        content = response.content.decode("utf-8")
        payload = json.loads(content)
        eppn = payload["user"]["eppn"]
        password = payload["user"]["password"]
        assert self._is_presentable_format(password)

        response = self.client.post(url="/Users/reset_password", json={"eppn": eppn}, headers=headers)
        assert response.status_code == HTTPStatus.OK

        content = response.content.decode("utf-8")
        payload = json.loads(content)
        assert payload["status"] == "success"
        assert payload["user"]["eppn"] == eppn
        assert payload["user"]["given_name"] == self.user1["given_name"]
        assert payload["user"]["surname"] == self.user1["surname"]
        assert payload["user"]["password"] is not None
        new_password = payload["user"]["password"]
        assert self._is_presentable_format(new_password)

    def test_remove_error(self) -> None:
        token = self._make_bearer_token(claims=self.claims)

        headers = self.headers
        headers["Authorization"] = f"Bearer {token}"

        response = self.client.post(url="/Users/remove", json={"eppn": "made_up"}, headers=headers)
        assert response.status_code == HTTPStatus.OK

    def test_reset_error(self) -> None:
        token = self._make_bearer_token(claims=self.claims)

        headers = self.headers
        headers["Authorization"] = f"Bearer {token}"
        response = self.client.post(url="/Users/reset_password", json={"eppn": "made_up"}, headers=headers)
        assert response.status_code == HTTPStatus.NOT_FOUND
