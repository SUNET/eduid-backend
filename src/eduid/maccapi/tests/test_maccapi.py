import json
from eduid.maccapi.testing import MAccApiTestCase


class TestMAccApi(MAccApiTestCase):
    def setUp(self) -> None:
        self.user1 = { "given_name": "Test", "surname": "User" }
        self.user2 = { "given_name": "Test", "surname": "User2" }
        return super().setUp()
    
    def test_create_user(self):
        response = self.client.post(url="/Users/create", json=self.user1)
        assert response.status_code == 200

        content = response.content.decode("utf-8")
        payload = json.loads(content)
        
        assert payload["status"] == "success"
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