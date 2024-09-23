from typing import Any
from uuid import uuid4

from eduid.common.models.scim_base import SCIMResourceType, SCIMSchema
from eduid.common.utils import make_etag
from eduid.queue.db.queue_item import QueueItem
from eduid.scimapi.testing import ScimApiTestCase
from eduid.userdb.scimapi import EventLevel

__author__ = "lundberg"


class TestNotifications(ScimApiTestCase):
    def _get_notifications(self):
        return [QueueItem.from_dict(x) for x in self.messagedb._get_all_docs()]

    def _get_config(self) -> dict[str, Any]:
        config = super()._get_config()
        config["data_owners"]["eduid.se"]["notify"] = ["https://example.org/notify"]
        return config

    def test_create_user_notification(self):
        assert len(self._get_notifications()) == 0

        req = {"schemas": [SCIMSchema.CORE_20_USER.value], "externalId": "test-id-1"}
        response = self.client.post(url="/Users/", json=req, headers=self.headers)
        self._assertResponse(response, status_code=201)

        assert len(self._get_notifications()) == 1

    def test_create_group_notification(self):
        assert len(self._get_notifications()) == 0

        req = {"schemas": [SCIMSchema.CORE_20_GROUP.value], "externalId": "test-id-1", "displayName": "Test Group"}
        response = self.client.post(url="/Groups/", json=req, headers=self.headers)
        self._assertResponse(response, status_code=201)

        assert len(self._get_notifications()) == 1

    def test_create_event_notification(self):
        assert len(self._get_notifications()) == 0

        user = self.add_user(identifier=str(uuid4()), external_id="test@example.org")
        assert user
        event = {
            "resource": {
                "resourceType": SCIMResourceType.USER.value,
                "id": str(user.scim_id),
                "version": make_etag(user.version),
                "lastModified": str(user.last_modified),
            },
            "level": EventLevel.ERROR.value,
            "data": {"create_test": True},
        }
        req = {"schemas": [SCIMSchema.NUTID_EVENT_V1.value], SCIMSchema.NUTID_EVENT_V1.value: event}
        result = self.client.post(url="/Events/", json=req, headers=self.headers)
        self._assertResponse(result)

        notifications = self._get_notifications()
        assert len(notifications) == 1

        this = notifications[0]
        assert this.payload.to_dict()["data_owner"] == "eduid.se"
        assert this.payload.to_dict()["post_url"] == "https://example.org/notify"
