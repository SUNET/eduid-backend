# -*- coding: utf-8 -*-
import logging
import random
from datetime import datetime, timedelta, timezone

from pymongo.errors import ServerSelectionTimeoutError, NotMasterError

from eduid_queue.db import QueueDB
from eduid_queue.db.message import EduidInviteEmail
from eduid_queue.db.queue_item import SenderInfo, QueueItem
from eduid_queue.testing import MongoTemporaryInstanceReplicaSet

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


tmp_db = MongoTemporaryInstanceReplicaSet.get_instance()
print(f'{tmp_db.uri}')

while True:
    try:
        db = QueueDB(db_uri=tmp_db.uri, collection='messages')
    except ServerSelectionTimeoutError as e:
        print(f'mongodb not ready: {e}')
        print(f'{tmp_db.output}')
        continue
    except NotMasterError:
        continue
    break


loop = 0
while True:
    try:
        sender_info = SenderInfo('localhost', 'test_node')
        expires_at = datetime.now(tz=timezone.utc) + timedelta(minutes=10)
        discard_at = expires_at + timedelta(minutes=1)
        # payload = TestPayload(message=f'this is test {loop}', created_ts=datetime.now(tz=timezone.utc))
        language = random.choice(['sv_SE', 'en_US', 'not_a_lang', 'sv', 'en'])
        payload = EduidInviteEmail(
            email='test@example.com',
            reference=f'test_reference_{loop}',
            invite_link='https://example.com/invite',
            invite_code='abc123',
            inviter_name='Inviter Name',
            language=language,
        )

        item = QueueItem(
            version=1,
            expires_at=expires_at,
            discard_at=discard_at,
            sender_info=sender_info,
            payload_type=payload.get_type(),
            payload=payload,
        )
        loop += 1
        print(item)
        try:
            ret = db.save(item)
        except ServerSelectionTimeoutError as e:
            print('mongodb not ready: {e}')
            continue
        print(ret)
        # wait for input
        input()
    except KeyboardInterrupt as e:
        print(e)
        exit(0)
