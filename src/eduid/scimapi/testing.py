# -*- coding: utf-8 -*-
import json
import unittest
import uuid
from dataclasses import asdict
from typing import Any, Dict, List, Mapping, Optional, Union

from bson import ObjectId
from requests import Response
from starlette.testclient import TestClient

from eduid.common.config.parsers import load_config
from eduid.common.config.testing import EtcdTemporaryInstance
from eduid.graphdb.testing import Neo4jTemporaryInstance
from eduid.queue.db.message import MessageDB
from eduid.scimapi.app import init_api
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.context import Context
from eduid.scimapi.db.common import ScimApiLinkedAccount, ScimApiName
from eduid.scimapi.db.eventdb import ScimApiEvent
from eduid.scimapi.db.groupdb import ScimApiGroup
from eduid.scimapi.db.invitedb import ScimApiInvite
from eduid.scimapi.db.userdb import ScimApiProfile, ScimApiUser
from eduid.scimapi.models.scimbase import SCIMSchema
from eduid.userdb.signup import SignupInviteDB
from eduid.userdb.testing import MongoTemporaryInstance

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
            'debug': True,
            'testing': True,
            'mongo_uri': self.mongo_uri,
            'data_owners': {'eduid.se': {'db_name': 'eduid_se'}},
            'logging_config': {
                'loggers': {
                    #'eduid_groupdb': {'handlers': ['console'], 'level': 'DEBUG'},
                    'neo4j': {'handlers': ['console'], 'level': 'WARNING'},
                    'root': {'handlers': ['console'], 'level': 'DEBUG'},
                },
            },
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

    def setUp(self) -> None:
        self.test_config = self._get_config()
        config = load_config(typ=ScimApiConfig, app_name='scimapi', ns='api', test_config=self.test_config)
        self.context = Context(config=config)

        # TODO: more tests for scoped groups when that is implemented
        self.data_owner = 'eduid.se'
        self.userdb = self.context.get_userdb(self.data_owner)
        self.invitedb = self.context.get_invitedb(self.data_owner)
        self.signup_invitedb = SignupInviteDB(db_uri=config.mongo_uri)
        self.messagedb = MessageDB(db_uri=config.mongo_uri)
        self.eventdb = self.context.get_eventdb(self.data_owner)

        self.api = init_api(name='test_api', test_config=self.test_config)
        self.client = TestClient(self.api)
        self.headers = {
            'Content-Type': 'application/scim+json',
            'Accept': 'application/scim+json',
        }

    def add_user(
        self,
        identifier: str,
        external_id: Optional[str] = None,
        profiles: Optional[Dict[str, ScimApiProfile]] = None,
        linked_accounts: Optional[List[ScimApiLinkedAccount]] = None,
    ) -> Optional[ScimApiUser]:
        user = ScimApiUser(user_id=ObjectId(), scim_id=uuid.UUID(identifier), external_id=external_id)
        if profiles:
            for key, value in profiles.items():
                user.profiles[key] = value
        if linked_accounts:
            user.linked_accounts = linked_accounts
        assert self.userdb
        self.userdb.save(user)
        return self.userdb.get_user_by_scim_id(scim_id=identifier)

    @staticmethod
    def as_json(data: dict) -> str:
        return json.dumps(data)

    def tearDown(self):
        super().tearDown()
        self.userdb._drop_whole_collection()
        self.eventdb._drop_whole_collection()

    def _assertScimError(
        self,
        json: Mapping[str, Any],
        schemas: Optional[List[str]] = None,
        status: int = 400,
        scim_type: Optional[str] = None,
        detail: Optional[Any] = None,
    ):
        if schemas is None:
            schemas = [SCIMSchema.ERROR.value]
        self.assertEqual(schemas, json.get('schemas'))
        self.assertEqual(status, json.get('status'))
        if scim_type is not None:
            self.assertEqual(scim_type, json.get('scimType'))
        if detail is not None:
            self.assertEqual(detail, json.get('detail'))

    def _assertScimResponseProperties(
        self,
        response: Response,
        resource: Union[ScimApiGroup, ScimApiUser, ScimApiInvite, ScimApiEvent],
        expected_schemas: List[str],
    ):
        if SCIMSchema.NUTID_USER_V1.value in response.json():
            # The API can always add this extension to the parsed_response, even if it was not in the request
            expected_schemas += [SCIMSchema.NUTID_USER_V1.value]

        if SCIMSchema.NUTID_GROUP_V1.value in response.json():
            # The API can always add this extension to the parsed_response, even if it was not in the request
            expected_schemas += [SCIMSchema.NUTID_GROUP_V1.value]

        if SCIMSchema.NUTID_INVITE_V1.value in response.json():
            # The API can always add this extension to the parsed_response, even if it was not in the request
            expected_schemas += [SCIMSchema.NUTID_INVITE_V1.value]

        if SCIMSchema.NUTID_EVENT_V1.value in response.json():
            # The API can always add this extension to the parsed_response, even if it was not in the request
            expected_schemas += [SCIMSchema.NUTID_EVENT_V1.value]

        response_schemas = response.json().get('schemas')
        self.assertIsInstance(response_schemas, list, 'Response schemas not present, or not a list')
        self.assertEqual(
            sorted(set(expected_schemas)), sorted(set(response_schemas)), 'Unexpected schema(s) in parsed_response'
        )

        if isinstance(resource, ScimApiUser):
            expected_location = f'http://localhost:8000/Users/{resource.scim_id}'
            expected_resource_type = 'User'
        elif isinstance(resource, ScimApiGroup):
            expected_location = f'http://localhost:8000/Groups/{resource.scim_id}'
            expected_resource_type = 'Group'
        elif isinstance(resource, ScimApiInvite):
            expected_location = f'http://localhost:8000/Invites/{resource.scim_id}'
            expected_resource_type = 'Invite'
        elif isinstance(resource, ScimApiEvent):
            expected_location = f'http://localhost:8000/Events/{resource.scim_id}'
            expected_resource_type = 'Event'
        else:
            raise ValueError('Resource is neither ScimApiUser, ScimApiGroup, ScimApiInvite or ScimApiEvent')

        self.assertEqual(str(resource.scim_id), response.json().get('id'), 'Unexpected id in parsed_response')

        self.assertEqual(
            expected_location,
            response.headers.get('location'),
            'Unexpected group resource location in parsed_response headers',
        )

        meta = response.json().get('meta')
        self.assertIsNotNone(meta, 'No meta in parsed_response')
        self.assertIsNotNone(meta.get('created'), 'No meta.created')
        self.assertIsNotNone(meta.get('lastModified'), 'No meta.lastModified')
        self.assertIsNotNone(meta.get('version'), 'No meta.version')
        self.assertEqual(expected_location, meta.get('location'), 'Unexpected group resource location')
        self.assertEqual(
            expected_resource_type, meta.get('resourceType'), f'meta.resourceType is not {expected_resource_type}'
        )

    @staticmethod
    def _assertName(db_name: ScimApiName, response_name: Dict[str, str]):
        name_map = [
            ('family_name', 'familyName'),
            ('given_name', 'givenName'),
            ('formatted', 'formatted'),
            ('middle_name', 'middleName'),
            ('honorific_prefix', 'honorificPrefix'),
            ('honorific_suffix', 'honorificSuffix'),
        ]
        db_name_dict = asdict(db_name)
        for first, second in name_map:
            assert db_name_dict.get(first) == response_name.get(
                second
            ), f'{first}:{db_name_dict.get(first)} != {second}:{response_name.get(second)}'

    @staticmethod
    def _assertResponse(response: Response, status_code: int = 200):
        _detail = None
        if response.json():
            _detail = response.json().get('detail', 'No error detail in parsed_response')
        assert (
            response.status_code == status_code
        ), f'Response status was not {status_code} ({response.status_code}), {_detail}'
