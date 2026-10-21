import logging
import os
from dataclasses import replace
from datetime import timedelta

from eduid.common.misc.timeutil import utc_now
from eduid.queue.db import Payload, QueueItem, SenderInfo
from eduid.queue.db.client import deterministic_item_id
from eduid.queue.db.message import MessageDB

logger = logging.getLogger(__name__)

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


def enqueue_email(
    messagedb: MessageDB,
    app_name: str,
    payload: Payload,
    expires_in: timedelta,
    dedup_key: str | None = None,
) -> QueueItem:
    """
    Create a queue item for an email payload and save it in the message queue.

    :param messagedb: Message queue database
    :param app_name: Name of the sending application
    :param payload: The email payload
    :param expires_in: How long the queue item is valid
    :param dedup_key: Optional stable key making the call idempotent. The item gets a deterministic item_id derived
        from the key and is inserted only if no item with that id exists, so repeating the call (e.g. a retry after
        a crash) does not queue a second mail while the first is still in the queue. An already queued mail is
        treated as success. Items handled by the mail worker are removed, so the protection ends then.
    :returns: The saved queue item (the item that would have been saved, if it was already queued)
    """
    message = init_queue_item(app_name=app_name, expires_in=expires_in, payload=payload)
    if dedup_key is None:
        messagedb.save(message)
        return message
    message = replace(message, item_id=deterministic_item_id(dedup_key))
    if not messagedb.save_if_absent(message):
        logger.info(f"Mail with dedup key {dedup_key} is already queued")
    return message
