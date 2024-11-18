import os
import unittest
import uuid
from collections.abc import Mapping
from dataclasses import asdict
from json import JSONDecodeError
from typing import Any

import pkg_resources
from bson import ObjectId
from httpx import Response
from starlette.testclient import TestClient

from eduid.common.config.base import DataOwnerName
from eduid.common.config.parsers import load_config
from eduid.common.models.scim_base import SCIMSchema
from eduid.common.testing_base import normalised_data
from eduid.graphdb.groupdb import User as GraphUser
from eduid.graphdb.testing import Neo4jTemporaryInstance
from eduid.queue.db.message import MessageDB
from eduid.scimapi.app import init_api
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.context import Context
from eduid.userdb.scimapi import ScimApiEvent, ScimApiGroup, ScimApiLinkedAccount, ScimApiName
from eduid.userdb.scimapi.invitedb import ScimApiInvite
from eduid.userdb.scimapi.userdb import ScimApiProfile, ScimApiUser
from eduid.userdb.signup import SignupInviteDB
from eduid.userdb.testing import MongoTemporaryInstance

__author__ = "lundberg"


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

    def _get_config(self) -> dict[str, Any]:
        config = {
            "debug": True,
            "testing": True,
            "mongo_uri": self.mongo_uri,
            "data_owners": {"eduid.se": {"db_name": "eduid_se"}},
            "logging_config": {
                "loggers": {
                    "neo4j": {"handlers": ["console"], "level": "WARNING"},
                    "root": {"handlers": ["console"], "level": "DEBUG"},
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
            {
                "neo4j_uri": self.neo4j_uri,
                "neo4j_config": {"encrypted": False},
            }
        )
        return config

    @classmethod
    def setUpClass(cls) -> None:
        cls.neo4j_instance = Neo4jTemporaryInstance.get_instance()
        cls.neo4j_uri = (
            f"bolt://{cls.neo4j_instance.DEFAULT_USERNAME}:{cls.neo4j_instance.DEFAULT_PASSWORD}"
            f"@localhost:{cls.neo4j_instance.bolt_port}"
        )
        super().setUpClass()


class ScimApiTestCase(MongoNeoTestCase):
    """Base test case providing the real API"""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()

    def setUp(self) -> None:
        if "EDUID_CONFIG_YAML" not in os.environ:
            os.environ["EDUID_CONFIG_YAML"] = "YAML_CONFIG_NOT_USED"

        self.datadir = pkg_resources.resource_filename(__name__, "tests/data")
        self.test_config = self._get_config()
        config = load_config(typ=ScimApiConfig, app_name="scimapi", ns="api", test_config=self.test_config)
        self.context = Context(config=config)

        # TODO: more tests for scoped groups when that is implemented
        self.data_owner = DataOwnerName("eduid.se")
        self.userdb = self.context.get_userdb(self.data_owner)
        self.groupdb = self.context.get_groupdb(self.data_owner)
        self.invitedb = self.context.get_invitedb(self.data_owner)
        self.signup_invitedb = SignupInviteDB(db_uri=config.mongo_uri)
        self.messagedb = MessageDB(db_uri=config.mongo_uri)
        self.eventdb = self.context.get_eventdb(self.data_owner)

        self.api = init_api(name="test_api", test_config=self.test_config)
        self.client = TestClient(self.api)
        self.headers = {
            "Content-Type": "application/scim+json",
            "Accept": "application/scim+json",
        }

    def _get_config(self) -> dict:
        config = super()._get_config()
        config["keystore_path"] = f"{self.datadir}/testing_jwks.json"
        config["signing_key_id"] = "testing-scimapi-2106210000"
        config["authorization_mandatory"] = False
        return config

    def add_user(
        self,
        identifier: str,
        external_id: str | None = None,
        profiles: dict[str, ScimApiProfile] | None = None,
        linked_accounts: list[ScimApiLinkedAccount] | None = None,
        name: ScimApiName | None = None,
    ) -> ScimApiUser:
        user = ScimApiUser(
            user_id=ObjectId(),
            scim_id=uuid.UUID(identifier),
            external_id=external_id,
            name=name,
        )
        if profiles:
            for key, value in profiles.items():
                user.profiles[key] = value
        if linked_accounts:
            user.linked_accounts = linked_accounts
        assert self.userdb
        self.userdb.save(user)
        saved_user = self.userdb.get_user_by_scim_id(scim_id=identifier)
        assert saved_user is not None  # please mypy
        return saved_user

    def add_group_with_member(self, group_identifier: str, display_name: str, user_identifier: str) -> ScimApiGroup:
        group = ScimApiGroup(scim_id=uuid.UUID(group_identifier), display_name=display_name)
        group.add_member(GraphUser(identifier=user_identifier, display_name="Test Member 1"))
        assert self.groupdb
        self.groupdb.save(group)
        saved_group = self.groupdb.get_group_by_scim_id(scim_id=group_identifier)
        assert saved_group is not None
        return saved_group

    def add_member_to_group(self, group_identifier: str, user_identifier: str) -> ScimApiGroup | None:
        assert self.groupdb
        group = self.groupdb.get_group_by_scim_id(scim_id=group_identifier)
        assert group is not None  # please mypy
        num_members = len(group.members)
        group.add_member(GraphUser(identifier=user_identifier, display_name=f"Test Member {num_members + 1}"))
        self.groupdb.save(group)
        return self.groupdb.get_group_by_scim_id(scim_id=group_identifier)

    def add_owner_to_group(self, group_identifier: str, user_identifier: str) -> ScimApiGroup | None:
        assert self.groupdb
        group = self.groupdb.get_group_by_scim_id(scim_id=group_identifier)
        assert group is not None  # please mypy
        num_owners = len(group.owners)
        group.add_owner(GraphUser(identifier=user_identifier, display_name=f"Test Owner {num_owners + 1}"))
        self.groupdb.save(group)
        return self.groupdb.get_group_by_scim_id(scim_id=group_identifier)

    def tearDown(self) -> None:
        super().tearDown()
        if self.userdb:
            self.userdb._drop_whole_collection()
        if self.eventdb:
            self.eventdb._drop_whole_collection()
        if self.invitedb:
            self.invitedb._drop_whole_collection()
        if self.signup_invitedb:
            self.signup_invitedb._drop_whole_collection()
        if self.messagedb:
            self.messagedb._drop_whole_collection()
        if self.groupdb:
            self.groupdb._drop_whole_collection()
            self.neo4j_instance.purge_db()

    def _assertScimError(
        self,
        json: Mapping[str, Any],
        schemas: list[str] | None = None,
        status: int = 400,
        scim_type: str | None = None,
        detail: object | None = None,
        exclude_keys: list[str] | None = None,
    ) -> None:
        if schemas is None:
            schemas = [SCIMSchema.ERROR.value]
        self.assertEqual(schemas, json.get("schemas"))
        self.assertEqual(status, json.get("status"))
        if scim_type is not None:
            self.assertEqual(scim_type, json.get("scimType"))
        if detail is not None:
            expected = normalised_data(detail)
            generated = normalised_data(json.get("detail"), exclude_keys=exclude_keys)
            assert expected == generated, f"Wrong error message: {generated}"

    def _assertScimResponseProperties(
        self,
        response: Response,
        resource: ScimApiGroup | ScimApiUser | ScimApiInvite | ScimApiEvent,
        expected_schemas: list[str],
    ) -> None:
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

        response_schemas = response.json().get("schemas")
        self.assertIsInstance(response_schemas, list, "Response schemas not present, or not a list")
        self.assertEqual(
            sorted(set(expected_schemas)), sorted(set(response_schemas)), "Unexpected schema(s) in parsed_response"
        )

        if isinstance(resource, ScimApiUser):
            expected_location = f"http://localhost:8000/Users/{resource.scim_id}"
            expected_resource_type = "User"
        elif isinstance(resource, ScimApiGroup):
            expected_location = f"http://localhost:8000/Groups/{resource.scim_id}"
            expected_resource_type = "Group"
        elif isinstance(resource, ScimApiInvite):
            expected_location = f"http://localhost:8000/Invites/{resource.scim_id}"
            expected_resource_type = "Invite"
        elif isinstance(resource, ScimApiEvent):
            expected_location = f"http://localhost:8000/Events/{resource.scim_id}"
            expected_resource_type = "Event"
        else:
            raise ValueError("Resource is neither ScimApiUser, ScimApiGroup, ScimApiInvite or ScimApiEvent")

        self.assertEqual(str(resource.scim_id), response.json().get("id"), "Unexpected id in parsed_response")

        self.assertEqual(
            expected_location,
            response.headers.get("location"),
            "Unexpected group resource location in parsed_response headers",
        )

        meta = response.json().get("meta")
        self.assertIsNotNone(meta, "No meta in parsed_response")
        self.assertIsNotNone(meta.get("created"), "No meta.created")
        self.assertIsNotNone(meta.get("lastModified"), "No meta.lastModified")
        self.assertIsNotNone(meta.get("version"), "No meta.version")
        self.assertEqual(expected_location, meta.get("location"), "Unexpected group resource location")
        self.assertEqual(
            expected_resource_type, meta.get("resourceType"), f"meta.resourceType is not {expected_resource_type}"
        )

    @staticmethod
    def _assertName(db_name: ScimApiName, response_name: dict[str, str]) -> None:
        name_map = [
            ("family_name", "familyName"),
            ("given_name", "givenName"),
            ("formatted", "formatted"),
            ("middle_name", "middleName"),
            ("honorific_prefix", "honorificPrefix"),
            ("honorific_suffix", "honorificSuffix"),
        ]
        db_name_dict = asdict(db_name)
        for first, second in name_map:
            assert db_name_dict.get(first) == response_name.get(
                second
            ), f"{first}:{db_name_dict.get(first)} != {second}:{response_name.get(second)}"

    @staticmethod
    def _assertResponse(response: Response, status_code: int = 200) -> None:
        _detail = None
        try:
            if response.json():
                _detail = response.json().get("detail", "No error detail in parsed_response")
        except JSONDecodeError:
            pass
        assert (
            response.status_code == status_code
        ), f"Response status was not {status_code} ({response.status_code}), {_detail}"
