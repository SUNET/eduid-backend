# -*- coding: utf-8 -*-

import asyncio
import logging
from random import randint

from eduid_queue.db import QueueItem, TestPayload

__author__ = 'lundberg'

logger = logging.getLogger(__name__)

# TODO: Remove this file after initial dev


async def slow_print(queue_item: QueueItem):
    delay = randint(2, 5)
    await asyncio.sleep(delay)
    if isinstance(queue_item.payload, TestPayload):
        message = queue_item.payload.message
        print(f'{message} slept {delay}: {queue_item}')
        return True
    return False
