# -*- coding: utf-8 -*-
import unittest
from os import environ

from eduid_userdb import MongoDB
from eduid_userdb.testing import MongoTemporaryInstance

from eduid_common.config.testing import EtcdTemporaryInstance
from eduid_groupdb import Neo4jDB
from eduid_groupdb.testing import Neo4jTemporaryInstance

__author__ = 'lundberg'


class ScimApiTestCase(unittest.TestCase):
    """
    Base test case that sets up a temporary Neo4j instance
    """
    mongodb_instance: MongoTemporaryInstance
    mongo_uri: str

    etcd_instance: EtcdTemporaryInstance

    neo4j_instance: Neo4jTemporaryInstance
    neo4j_uri: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.mongodb_instance = MongoTemporaryInstance.get_instance()
        cls.mongo_uri = cls.mongodb_instance.uri
        cls.neo4j_instance = Neo4jTemporaryInstance.get_instance()
        cls.neo4j_uri = f'bolt://{cls.neo4j_instance.DEFAULT_USERNAME}:{cls.neo4j_instance.DEFAULT_PASSWORD}' \
                        f'@localhost:{cls.neo4j_instance.bolt_port}'
        cls.etcd_instance = EtcdTemporaryInstance.get_instance()
        environ.update({'ETCD_PORT': str(cls.etcd_instance.port)})

    def tearDown(self):
        # Mongodb collection need to be cleared in every test class
        self.etcd_instance.clear('/eduid/api/')
        self.neo4j_instance.purge_db()
