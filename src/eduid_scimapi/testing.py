# -*- coding: utf-8 -*-
import json
import unittest
import uuid
from os import environ
from typing import Dict, Optional

from bson import ObjectId
from falcon.testing import TestClient

from eduid_common.config.testing import EtcdTemporaryInstance
from eduid_groupdb.testing import Neo4jTemporaryInstance
from eduid_userdb.testing import MongoTemporaryInstance

from eduid_scimapi.app import init_api
from eduid_scimapi.config import ScimApiConfig
from eduid_scimapi.context import Context
from eduid_scimapi.userdb import Profile, ScimApiUser

__author__ = 'lundberg'


class BaseDBTestCase(unittest.TestCase):
    """
    Base test case that sets up a temporary mongodb instance
    """

    mongodb_instance: MongoTemporaryInstance
    mongo_uri: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.mongodb_instance = MongoTemporaryInstance.get_instance()
        cls.mongo_uri = cls.mongodb_instance.uri

    def _get_config(self) -> dict:
        config = {
            'test': True,
            'mongo_uri': self.mongo_uri,
            'logging_config': None,
            'log_format': '%(asctime)s | %(levelname)s | %(name)s | %(module)s | %(message)s',
        }
        return config


class MongoNeoTestCase(BaseDBTestCase):
    """
    Base test case that sets up a temporary Neo4j instance
    """

    neo4j_instance: Neo4jTemporaryInstance
    neo4j_uri: str

    def _get_config(self) -> dict:
        config = super()._get_config()
        config.update(
            {'neo4j_uri': self.neo4j_uri, 'neo4j_config': {'encrypted': False},}
        )
        return config

    @classmethod
    def setUpClass(cls) -> None:
        cls.neo4j_instance = Neo4jTemporaryInstance.get_instance()
        cls.neo4j_uri = (
            f'bolt://{cls.neo4j_instance.DEFAULT_USERNAME}:{cls.neo4j_instance.DEFAULT_PASSWORD}'
            f'@localhost:{cls.neo4j_instance.bolt_port}'
        )
        super().setUpClass()

    def tearDown(self):
        super().tearDown()
        self.neo4j_instance.purge_db()


class ScimApiTestCase(MongoNeoTestCase):
    """ Base test case providing the real API """

    etcd_instance: EtcdTemporaryInstance

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.etcd_instance = EtcdTemporaryInstance.get_instance()
        environ.update({'ETCD_PORT': str(cls.etcd_instance.port)})

    def setUp(self) -> None:
        self.test_config = self._get_config()
        config = ScimApiConfig.init_config(test_config=self.test_config, debug=True)
        self.context = Context(name='test_app', config=config)

        # TODO: more tests for scoped groups when that is implemented
        self.data_owner = 'eduid.se'
        self.userdb = self.context.get_userdb(self.data_owner)

        api = init_api(name='test_api', test_config=self.test_config, debug=True)
        self.client = TestClient(api)
        self.headers = {
            'Content-Type': 'application/scim+json',
            'Accept': 'application/scim+json',
        }

    def add_user(
        self, identifier: str, external_id: str, profiles: Optional[Dict[str, Profile]] = None
    ) -> Optional[ScimApiUser]:
        user = ScimApiUser(user_id=ObjectId(), scim_id=uuid.UUID(identifier), external_id=external_id)
        if profiles:
            for key, value in profiles.items():
                user.profiles[key] = value
        assert self.userdb
        self.userdb.save(user)
        return self.userdb.get_user_by_scim_id(scim_id=identifier)

    @staticmethod
    def as_json(data: dict) -> str:
        return json.dumps(data)

    def tearDown(self):
        super().tearDown()
        self.userdb._drop_whole_collection()
        self.etcd_instance.clear('/eduid/api/')
