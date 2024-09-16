import os
from datetime import timedelta

from eduid.common.misc.timeutil import utc_now
from eduid.queue.db import Payload, QueueItem, SenderInfo

__author__ = "lundberg"


def init_queue_item(app_name: str, expires_in: timedelta, payload: Payload) -> QueueItem:
    system_hostname = os.environ.get("SYSTEM_HOSTNAME", "")  # Underlying hosts name for containers
    hostname = os.environ.get("HOSTNAME", "")  # Actual hostname or container id
    sender_info = SenderInfo(hostname=hostname, node_id=f"{app_name}@{system_hostname}")
    expires_at = utc_now() + expires_in
    discard_at = expires_at + timedelta(days=7)
    return QueueItem(
        version=1,
        expires_at=expires_at,
        discard_at=discard_at,
        sender_info=sender_info,
        payload_type=payload.get_type(),
        payload=payload,
    )
