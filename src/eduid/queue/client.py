import logging
import os
from dataclasses import replace
from datetime import timedelta

from eduid.common.misc.timeutil import utc_now
from eduid.queue.db import Payload, QueueItem, SenderInfo
from eduid.queue.db.client import deterministic_item_id
from eduid.queue.db.message import MessageDB
from eduid.queue.exceptions import QueueItemExpired

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
        treated as success, whether it is waiting or being processed by a worker (a worker removes an item when it
        is done, so the protection ends then). An already queued item that is expired is NOT success: the worker
        only logs expired items and never sends them, so QueueItemExpired is raised. The caller should keep its
        state pending and retry later; once retention (discard_at) removes the item the key can be queued again.
    :raises QueueItemExpired: the existing item with this key is expired
    :returns: The saved queue item (the item that would have been saved, if it was already queued)
    """
    message = init_queue_item(app_name=app_name, expires_in=expires_in, payload=payload)
    if dedup_key is None:
        messagedb.save(message)
        return message
    message = replace(message, item_id=deterministic_item_id(dedup_key))
    # Two attempts: the existing item can vanish (handled by a worker, discarded) between the failed insert and
    # the lookup, in which case the insert is retried once.
    for _ in range(2):
        if messagedb.save_if_absent(message):
            return message
        existing = messagedb.get_item_by_id(message.item_id, parse_payload=False)
        if existing is None:
            continue
        if existing.expires_at <= utc_now():
            raise QueueItemExpired(f"Mail with dedup key {dedup_key} is queued but expired, it will not be sent")
        logger.info(f"Mail with dedup key {dedup_key} is already queued")
        return message
    raise RuntimeError(f"Could not queue mail with dedup key {dedup_key}: item appears and vanishes repeatedly")
