# -*- coding: utf-8 -*-

from typing import Sequence

import pymongo
from pymongo.errors import ServerSelectionTimeoutError

from eduid_userdb.testing import MongoTemporaryInstance

__author__ = 'lundberg'


class MongoTemporaryInstanceReplicaSet(MongoTemporaryInstance):
    @property
    def command(self) -> Sequence[str]:
        return [
            'docker',
            'run',
            '--rm',
            '-p',
            f'{self.port}:27017',
            '-e',
            'REPLSET=yes',
            'docker.sunet.se/eduid/mongodb:latest',
        ]

    def setup_conn(self) -> bool:
        try:
            tmp_conn = pymongo.MongoClient('localhost', self.port)
            # Start replica set
            tmp_conn.admin.command("replSetInitiate")
            tmp_conn.close()
            self._conn = pymongo.MongoClient(host='localhost', port=self.port, replicaSet='rs0')
        except pymongo.errors.ConnectionFailure:
            return False
        return True

    @property
    def uri(self):
        return f'mongodb://localhost:{self.port}'
