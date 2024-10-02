__author__ = "lundberg"

import json
import logging
from datetime import datetime, timedelta
from os import environ
from typing import TYPE_CHECKING, Any, NewType

from eduid.common.config.base import DataOwnerName
from eduid.queue.db import QueueItem, SenderInfo
from eduid.queue.db.message.payload import EduidSCIMAPINotification
from eduid.scimapi.config import ScimApiConfig

if TYPE_CHECKING:
    from eduid.scimapi.context import Context

logger = logging.getLogger(__name__)

TFormattedMessage = NewType("TFormattedMessage", str)


class NotificationRelay:
    def __init__(self, config: ScimApiConfig) -> None:
        self.config = config
        app_name = config.app_name
        system_hostname = environ.get("SYSTEM_HOSTNAME", "")  # Underlying hosts name for containers
        hostname = environ.get("HOSTNAME", "")  # Actual hostname or container id
        self.sender_info = SenderInfo(hostname=hostname, node_id=f"{app_name}@{system_hostname}")

    def _urls_for(self, data_owner: DataOwnerName) -> list[str]:
        if data_owner not in self.config.data_owners:
            return []
        return self.config.data_owners[data_owner].notify

    def format_message(self, version: int, data: dict[str, Any]) -> TFormattedMessage:
        if version != 1:
            raise NotImplementedError(f"version {version} not implemented")
        return TFormattedMessage(json.dumps({"v": version, "location": data["location"]}))

    def notify(self, data_owner: DataOwnerName, message: TFormattedMessage, context: "Context") -> None:
        """
        Send a request for 'someone else' to POST information about this event to a URL.
        """
        expires_at = datetime.utcnow() + timedelta(seconds=self.config.invite_expire)
        discard_at = expires_at + timedelta(days=7)
        _urls = self._urls_for(data_owner)
        if not _urls:
            context.logger.debug(f"No notification urls for data owner {data_owner}")
            return None
        for post_url in _urls:
            payload = EduidSCIMAPINotification(data_owner=data_owner, message=message, post_url=post_url)
            item = QueueItem(
                version=1,
                expires_at=expires_at,
                discard_at=discard_at,
                sender_info=self.sender_info,
                payload_type=payload.get_type(),
                payload=payload,
            )
            context.messagedb.save(item)
            context.logger.info(f"Saved notification {item.item_id} in message queue")
