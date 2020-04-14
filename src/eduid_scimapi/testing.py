# -*- coding: utf-8 -*-
import json
import unittest
from os import environ

import falcon
from falcon.testing import TestClient

from eduid_common.config.testing import EtcdTemporaryInstance
from eduid_userdb.testing import MongoTemporaryInstance

from eduid_groupdb.testing import Neo4jTemporaryInstance
from eduid_scimapi.app import init_api
from eduid_scimapi.config import ScimApiConfig

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
        cls.neo4j_uri = (
            f'bolt://{cls.neo4j_instance.DEFAULT_USERNAME}:{cls.neo4j_instance.DEFAULT_PASSWORD}'
            f'@localhost:{cls.neo4j_instance.bolt_port}'
        )
        cls.etcd_instance = EtcdTemporaryInstance.get_instance()
        environ.update({'ETCD_PORT': str(cls.etcd_instance.port)})

    def setUp(self) -> None:
        self.test_config = self._get_config()
        api = init_api(name='test_api', test_config=self.test_config, debug=True)
        self.client = TestClient(api)
        self.headers = {
            'Content-Type': 'application/scim+json',
            'Accept': 'application/scim+json',
        }

    def _get_config(self) -> dict:
        config = {
            'test': True,
            'mongo_uri': self.mongo_uri,
            'neo4j_uri': self.neo4j_uri,
            'neo4j_config': {'encrypted': False},
            'logging_config': None,
            'log_format': '%(asctime)s | %(levelname)s | %(name)s | %(module)s | %(message)s',
        }
        return config

    def as_json(self, data: dict) -> str:
        return json.dumps(data)

    def tearDown(self):
        # Mongodb collection need to be cleared in every test class
        self.etcd_instance.clear('/eduid/api/')
        self.neo4j_instance.purge_db()
