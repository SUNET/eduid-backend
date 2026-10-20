import os
from datetime import timedelta

from eduid.common.misc.timeutil import utc_now
from eduid.queue.db import Payload, QueueItem, SenderInfo
from eduid.queue.db.message import MessageDB

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


def enqueue_email(messagedb: MessageDB, app_name: str, payload: Payload, expires_in: timedelta) -> QueueItem:
    """
    Create a queue item for an email payload and save it in the message queue.

    :param messagedb: Message queue database
    :param app_name: Name of the sending application
    :param payload: The email payload
    :param expires_in: How long the queue item is valid
    :returns: The saved queue item
    """
    message = init_queue_item(app_name=app_name, expires_in=expires_in, payload=payload)
    messagedb.save(message)
    return message
