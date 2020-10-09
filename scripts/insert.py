# -*- coding: utf-8 -*-

from datetime import datetime, timedelta, timezone
from typing import Sequence

from pymongo.errors import ServerSelectionTimeoutError

from eduid_userdb.q import QueueItem, SenderInfo, TestPayload
from eduid_userdb.q.db import QueueDB
from eduid_userdb.testing import MongoTemporaryInstance

__author__ = 'lundberg'


class MongoTemporaryInstanceReplicaSet(MongoTemporaryInstance):
    @property
    def command(self) -> Sequence[str]:
        return ['docker', 'run', '--rm', '-p', '{!s}:27017'.format(self._port), 'docker.sunet.se/eduid/mongodb:latest']


tmp_db = MongoTemporaryInstance.get_instance()
#db_uri = tmp_db.uri
db_uri = 'mongodb://localhost:43444'
print(f'{db_uri}')

while True:
    try:
        db = QueueDB(db_uri=db_uri, collection='test')
    except ServerSelectionTimeoutError as e:
        print(f'mongodb not ready: {e}')
        print(f'{tmp_db.output}')
        continue
    break


loop = 0
while True:
    try:
        sender_info = SenderInfo('localhost', 'test_node')
        expires_at = datetime.now(tz=timezone.utc) + timedelta(minutes=10)
        discard_at = expires_at + timedelta(minutes=1)
        payload = TestPayload(message=f'this is test {loop}', created_ts=datetime.now(tz=timezone.utc))

        item = QueueItem(version=1, expires_at=expires_at, discard_at=discard_at, sender_info=sender_info,
                         payload_type=payload.get_type(), payload=payload)
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
