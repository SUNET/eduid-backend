# -*- coding: utf-8 -*-
import logging
from datetime import datetime, timedelta, timezone
import random
from time import sleep
from typing import Sequence

import pymongo
from pymongo.errors import ServerSelectionTimeoutError, NotMasterError

from eduid_queue.db import QueueDB, TestPayload
from eduid_queue.db.message import EduidInviteEmail
from eduid_queue.db.queue_item import SenderInfo, QueueItem
from eduid_userdb.testing import MongoTemporaryInstance

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class MongoTemporaryInstanceReplicaSet(MongoTemporaryInstance):
    @property
    def command(self) -> Sequence[str]:
        return ['docker', 'run', '--rm', '-p', f'{self.port}:27017', 'local/mongodb']

    def setup_conn(self) -> bool:
        try:
            tmp_conn = pymongo.MongoClient('localhost', self.port)
            # Start replica set
            rs_conf = """{
                '_id': 'rs0',
                'members': [{'_id': 0, 'host': '0.0.0.0:27017'}],
            }"""

            tmp_conn.admin.command("replSetInitiate")
            tmp_conn.close()
            self._conn = pymongo.MongoClient(host='localhost', port=self.port, replicaSet='rs0')
        except pymongo.errors.ConnectionFailure:
            return False
        return True

    @property
    def uri(self):
        return f'mongodb://localhost:{self.port}'


tmp_db = MongoTemporaryInstanceReplicaSet.get_instance()
db_uri = tmp_db.uri
# db_uri = 'mongodb://localhost:43444'
print(f'{db_uri}')

while True:
    try:
        db = QueueDB(db_uri=db_uri, collection='test')
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
