__author__ = "lundberg"

import json
from http import HTTPStatus
from uuid import uuid4

from eduid.scimapi.testing import ScimApiTestCase


class TestLoginResource(ScimApiTestCase):
    def setUp(self) -> None:
        super().setUp()

    def _get_config(self) -> dict:
        config = super()._get_config()
        config["login_enabled"] = True
        return config

    def test_get_token(self) -> None:
        response = self.client.post(url="/login", content=json.dumps({"data_owner": "eduid.se"}), headers=self.headers)
        self._assertResponse(response)

    def test_use_token(self) -> None:
        response = self.client.post(url="/login", content=json.dumps({"data_owner": "eduid.se"}), headers=self.headers)
        token = response.headers.get("Authorization")
        headers = {
            "Content-Type": "application/scim+json",
            "Accept": "application/scim+json",
            "Authorization": f"{token}",
        }
        db_user = self.add_user(identifier=str(uuid4()), external_id="test-id-1")
        response = self.client.get(url=f"/Users/{db_user.scim_id}", headers=headers)
        self._assertResponse(response)


class TestLoginResourceNotEnabled(ScimApiTestCase):
    def setUp(self) -> None:
        super().setUp()

    def test_get_token(self) -> None:
        response = self.client.post(url="/login", content=json.dumps({"data_owner": "eduid.se"}), headers=self.headers)
        assert response.status_code == HTTPStatus.NOT_FOUND
