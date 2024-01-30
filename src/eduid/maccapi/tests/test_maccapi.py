import json
from typing import Any, Mapping

from jwcrypto import jwt

from eduid.common.config.base import EduidScope
from eduid.maccapi.testing import MAccApiTestCase


class TestMAccApi(MAccApiTestCase):
    def setUp(self) -> None:
        self.user1 = {"given_name": "Test", "surname": "User"}
        self.user2 = {"given_name": "Test", "surname": "User2"}
        return super().setUp()

    def _make_bearer_token(self, claims: Mapping[str, Any]) -> str:
        token = jwt.JWT(header={"alg": "ES256"}, claims=claims)
        jwk = list(self.context.jwks)[0]
        token.make_signed_token(jwk)
        return token.serialize()

    def test_create_user(self):
        response = self.client.post(url="/Users/create", json=self.user1)
        assert response.status_code == 200

        content = response.content.decode("utf-8")
        payload = json.loads(content)

        assert payload["status"] == "success"
        # production is default scope unless set to something else in config
        assert payload["scope"] == EduidScope.production
        assert payload["user"]["given_name"] == self.user1["given_name"]
        assert payload["user"]["surname"] == self.user1["surname"]
        assert payload["user"]["eppn"] != None
        assert payload["user"]["password"] != None

    def test_create_multiple_users(self):
        response = self.client.post(url="/Users/create", json=self.user1)
        assert response.status_code == 200
        response = self.client.post(url="/Users/create", json=self.user2)
        assert response.status_code == 200
        response = self.client.get(url="/Users")
        assert response.status_code == 200

        content = response.content.decode("utf-8")
        payload = json.loads(content)

        assert payload["status"] == "success"
        assert len(payload["users"]) == 2

    def test_remove_user(self):
        response = self.client.post(url="/Users/create", json=self.user1)
        assert response.status_code == 200

        content = response.content.decode("utf-8")
        payload = json.loads(content)
        eppn = payload["user"]["eppn"]

        response = self.client.post(url="/Users/remove", json={"eppn": eppn})

        content = response.content.decode("utf-8")
        payload = json.loads(content)
        assert payload["status"] == "success"
        assert payload["user"]["eppn"] == eppn
        assert payload["user"]["given_name"] == self.user1["given_name"]
        assert payload["user"]["surname"] == self.user1["surname"]

    def test_reset_password(self):
        response = self.client.post(url="/Users/create", json=self.user1)
        assert response.status_code == 200

        content = response.content.decode("utf-8")
        payload = json.loads(content)
        eppn = payload["user"]["eppn"]

        response = self.client.post(url="/Users/reset_password", json={"eppn": eppn})
        assert response.status_code == 200

        content = response.content.decode("utf-8")
        payload = json.loads(content)
        assert payload["status"] == "success"
        assert payload["user"]["eppn"] == eppn
        assert payload["user"]["given_name"] == self.user1["given_name"]
        assert payload["user"]["surname"] == self.user1["surname"]
        assert payload["user"]["password"] != None

    def test_auth_create_user(self):
        domain = "eduid.se"
        claims = {
            "version": 1,
            "scopes": [domain],
            "auth_source": "config",
            "requested_access": [{"type": "maccapi", "scope": "eduid.se"}],
        }
        token = self._make_bearer_token(claims=claims)

        headers = self.headers
        headers["Authorization"] = f"Bearer {token}"

        response = self.client.post(url="/Users/create", json=self.user1, headers=headers)
        assert response.status_code == 200

        content = response.content.decode("utf-8")
        payload = json.loads(content)

        assert payload["status"] == "success"
        assert payload["user"]["given_name"] == self.user1["given_name"]
        assert payload["user"]["surname"] == self.user1["surname"]
        assert payload["user"]["eppn"] != None
        assert payload["user"]["password"] != None
