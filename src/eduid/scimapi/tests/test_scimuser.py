import json
import logging
import unittest
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping, Optional
from uuid import UUID, uuid4

import bson
from bson import ObjectId
from httpx import Response

from eduid.common.models.scim_base import Email, LanguageTag, Meta, Name, PhoneNumber, SCIMResourceType, SCIMSchema
from eduid.common.models.scim_user import LinkedAccount, NutidUserExtensionV1, Profile, UserResponse
from eduid.common.testing_base import normalised_data
from eduid.scimapi.testing import ScimApiTestCase
from eduid.scimapi.utils import filter_none, make_etag
from eduid.userdb.scimapi import EventStatus, ScimApiLinkedAccount
from eduid.userdb.scimapi.userdb import ScimApiProfile, ScimApiUser

logger = logging.getLogger(__name__)


class TestScimUser(unittest.TestCase):
    def setUp(self) -> None:
        self.maxDiff = None
        self.user_doc1 = {
            "_id": ObjectId("5e5542db34a4cf8015e62ac8"),
            "scim_id": "9784e1bf-231b-4eb8-b315-52eb46dd7c4b",
            "external_id": "hubba-bubba@eduid.se",
            "name": {
                "family_name": "Testsson",
                "formatted": "Test Testsson",
                "given_name": "Test",
                "honorific_prefix": "Dr",
                "honorific_suffix": "III",
                "middle_name": "Testaren",
            },
            "emails": [{"primary": True, "type": "home", "value": "test@example.com"}],
            "phone_numbers": [{"primary": True, "type": "mobile", "value": "tel:+1-202-456-1414"}],
            "preferred_language": "en",
            "version": ObjectId("5e5e6829f86abf66d341d4a2"),
            "created": datetime.fromisoformat("2020-02-25T15:52:59.745"),
            "last_modified": datetime.fromisoformat("2020-02-25T15:52:59.745"),
            "profiles": {"student": {"attributes": {"displayName": "Test"}}},
        }

    def test_load_old_user(self):
        user = ScimApiUser.from_dict(self.user_doc1)
        self.assertEqual(user.profiles["student"].attributes["displayName"], "Test")

        # test to-dict+from-dict consistency
        user2 = ScimApiUser.from_dict(user.to_dict())
        self.assertEqual(asdict(user), asdict(user2))

    def test_to_scimuser_doc(self):
        db_user = ScimApiUser.from_dict(self.user_doc1)
        meta = Meta(
            location=f"http://example.org/Users/{db_user.scim_id}",
            resource_type=SCIMResourceType.USER,
            created=db_user.created,
            last_modified=db_user.last_modified,
            version=db_user.version,
        )

        user_response = UserResponse(
            id=db_user.scim_id,
            meta=meta,
            external_id=db_user.external_id,
            name=Name(**asdict(db_user.name)),
            emails=[Email(**asdict(email)) for email in db_user.emails],
            phone_numbers=[PhoneNumber(**asdict(number)) for number in db_user.phone_numbers],
            preferred_language=LanguageTag("en"),
            schemas=[SCIMSchema.CORE_20_USER, SCIMSchema.NUTID_USER_V1],
            groups=[],
            nutid_user_v1=NutidUserExtensionV1(
                profiles={name: Profile(**asdict(profile)) for name, profile in db_user.profiles.items()}
            ),
        )

        expected = {
            "emails": [{"primary": True, "type": "home", "value": "test@example.com"}],
            "externalId": "hubba-bubba@eduid.se",
            "groups": [],
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {"student": {"attributes": {"displayName": "Test"}, "data": {}}},
                "linked_accounts": [],
            },
            "id": "9784e1bf-231b-4eb8-b315-52eb46dd7c4b",
            "meta": {
                "created": "2020-02-25T15:52:59.745000",
                "lastModified": "2020-02-25T15:52:59.745000",
                "location": f"http://example.org/Users/{db_user.scim_id}",
                "resourceType": "User",
                "version": 'W/"5e5e6829f86abf66d341d4a2"',
            },
            "name": {
                "familyName": "Testsson",
                "formatted": "Test Testsson",
                "givenName": "Test",
                "honorificPrefix": "Dr",
                "honorificSuffix": "III",
                "middleName": "Testaren",
            },
            "phoneNumbers": [{"primary": True, "type": "mobile", "value": "tel:+1-202-456-1414"}],
            "preferredLanguage": "en",
            "schemas": [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
        }
        user_response_json = user_response.json(exclude_none=True, by_alias=True)
        loaded_user_response = json.loads(user_response_json)
        assert loaded_user_response == expected

    def test_to_scimuser_no_external_id(self):
        user_doc2 = {
            "_id": ObjectId("5e81c5f849ac2cd87580e500"),
            "scim_id": "a7851d21-eab9-4caa-ba5d-49653d65c452",
            "version": ObjectId("5e81c5f849ac2cd87580e502"),
            "created": datetime.fromisoformat("2020-03-30T10:12:08.528"),
            "last_modified": datetime.fromisoformat("2020-03-30T10:12:08.531"),
            "profiles": {"student": {"data": {}}},
        }
        db_user = ScimApiUser.from_dict(user_doc2)

        meta = Meta(
            location=f"http://example.org/Users/{db_user.scim_id}",
            resource_type=SCIMResourceType.USER,
            created=db_user.created,
            last_modified=db_user.last_modified,
            version=db_user.version,
        )

        user_response = UserResponse(
            id=db_user.scim_id,
            meta=meta,
            schemas=[SCIMSchema.CORE_20_USER, SCIMSchema.NUTID_USER_V1],
            external_id=db_user.external_id,
            groups=[],
            nutid_user_v1=NutidUserExtensionV1(
                profiles={name: Profile(**asdict(profile)) for name, profile in db_user.profiles.items()}
            ),
        )

        expected = {
            "schemas": [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
            "id": "a7851d21-eab9-4caa-ba5d-49653d65c452",
            "phoneNumbers": [],
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {"student": {"data": {}, "attributes": {}}},
                "linked_accounts": [],
            },
            "meta": {
                "version": 'W/"5e81c5f849ac2cd87580e502"',
                "created": "2020-03-30T10:12:08.528000",
                "resourceType": "User",
                "lastModified": "2020-03-30T10:12:08.531000",
                "location": f"http://example.org/Users/{db_user.scim_id}",
            },
            "name": {},
            "groups": [],
            "emails": [],
        }
        user_response_json = user_response.json(exclude_none=True, by_alias=True)
        loaded_user_response = json.loads(user_response_json)
        assert loaded_user_response == expected

    def test_bson_serialization(self):
        user = ScimApiUser.from_dict(self.user_doc1)
        x = bson.encode(user.to_dict())
        self.assertTrue(x)


@dataclass
class UserApiResult:
    request: Mapping[str, Any]
    response: Response
    nutid_user: Optional[NutidUserExtensionV1]
    parsed_response: Optional[UserResponse]


class ScimApiTestUserResourceBase(ScimApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.test_profile = ScimApiProfile(attributes={"displayName": "Test User 1"}, data={"test_key": "test_value"})

    def _assertUserUpdateSuccess(self, req: Mapping, response, user: ScimApiUser):
        """Function to validate successful responses to SCIM calls that update a user according to a request."""

        if response.json().get("schemas") == [SCIMSchema.ERROR.value]:
            self.fail(f"Got SCIM error parsed_response ({response.status}):\n{response.json}")

        expected_schemas = req.get("schemas", [SCIMSchema.CORE_20_USER.value])
        if SCIMSchema.NUTID_USER_V1.value in response.json() and SCIMSchema.NUTID_USER_V1.value not in expected_schemas:
            # The API can always add this extension to the parsed_response, even if it was not in the request
            expected_schemas += [SCIMSchema.NUTID_USER_V1.value]

        self._assertScimResponseProperties(response, resource=user, expected_schemas=expected_schemas)

        # Validate user update specifics
        assert user.external_id == response.json().get(
            "externalId"
        ), 'user.externalId != parsed_response.json().get("externalId")'
        self._assertName(user.name, response.json().get("name"))
        _expected_emails = filter_none(normalised_data([email.to_dict() for email in user.emails]))
        _obtained_emails = filter_none(normalised_data(response.json().get("emails", [])))
        assert _obtained_emails == _expected_emails, 'parsed_response.json().get("email") != user.emails'
        _expected_phones = filter_none(normalised_data([number.to_dict() for number in user.phone_numbers]))
        _obtained_phones = filter_none(normalised_data(response.json().get("phoneNumbers", [])))
        assert _obtained_phones == _expected_phones, 'parsed_response.json().get("phoneNumbers") != user.phone_numbers'
        assert user.preferred_language == response.json().get(
            "preferredLanguage"
        ), 'user.preferred_language != parsed_response.json().get("preferredLanguage")'

        # If the request has NUTID profiles, ensure they are present in the parsed_response
        if SCIMSchema.NUTID_USER_V1.value in req:
            req_nutid = req[SCIMSchema.NUTID_USER_V1.value]
            resp_nutid = response.json().get(SCIMSchema.NUTID_USER_V1.value)
            self.assertEqual(
                req_nutid,
                resp_nutid,
                "Unexpected NUTID user data in parsed_response",
            )
        elif SCIMSchema.NUTID_USER_V1.value in response.json:
            self.fail(f"Unexpected {SCIMSchema.NUTID_USER_V1.value} in the parsed_response")

    def _create_user(self, req: dict[str, Any], expect_success: bool = True) -> UserApiResult:
        if "schemas" not in req:
            _schemas = [SCIMSchema.CORE_20_USER.value]
            if SCIMSchema.NUTID_USER_V1.value in req:
                _schemas += [SCIMSchema.NUTID_USER_V1.value]
            req["schemas"] = _schemas
        response = self.client.post(url="/Users/", json=req, headers=self.headers)
        if expect_success:
            self._assertResponse(response, status_code=201)
        try:
            user_response = UserResponse.parse_raw(response.text)
            nutid_user = user_response.nutid_user_v1
        except Exception:
            if not expect_success:
                user_response = None
                nutid_user = None
            else:
                raise
        return UserApiResult(request=req, nutid_user=nutid_user, response=response, parsed_response=user_response)

    def _update_user(
        self, req: dict[str, Any], scim_id: UUID, version: Optional[ObjectId], expect_success: bool = True
    ) -> UserApiResult:
        if "schemas" not in req:
            _schemas = [SCIMSchema.CORE_20_USER.value]
            if SCIMSchema.NUTID_USER_V1.value in req:
                _schemas += [SCIMSchema.NUTID_USER_V1.value]
            req["schemas"] = _schemas
        if "id" not in req:
            req["id"] = str(scim_id)
        _headers = dict(self.headers)  # copy
        if version:
            _headers["IF-MATCH"] = make_etag(version)
        response = self.client.put(url=f"/Users/{scim_id}", json=req, headers=_headers)
        if expect_success:
            self._assertResponse(response)
        try:
            user_response = UserResponse.parse_raw(response.text)
            nutid_user = user_response.nutid_user_v1
        except Exception:
            if not expect_success:
                user_response = None
                nutid_user = None
            else:
                raise
        return UserApiResult(request=req, nutid_user=nutid_user, response=response, parsed_response=user_response)


class TestUserResource(ScimApiTestUserResourceBase):
    def test_get_user(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id="test-id-1", profiles={"test": self.test_profile})
        response = self.client.get(url=f"/Users/{db_user.scim_id}", headers=self.headers)

        _req = {
            SCIMSchema.NUTID_USER_V1.value: {"profiles": {"test": asdict(self.test_profile)}, "linked_accounts": []},
        }
        self._assertUserUpdateSuccess(_req, response, db_user)

    def test_create_users_with_no_external_id(self):
        self.add_user(identifier=str(uuid4()), profiles={"test": self.test_profile})
        self.add_user(identifier=str(uuid4()), profiles={"test": self.test_profile})

    def test_create_user(self):
        req = {
            "externalId": "test-id-1",
            "name": {"familyName": "Testsson", "givenName": "Test", "middleName": "Testaren"},
            "emails": [{"primary": True, "type": "home", "value": "test@example.com"}],
            "phoneNumbers": [{"primary": True, "type": "mobile", "value": "tel:+1-202-456-1414"}],
            "preferredLanguage": "en",
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {
                    "test": {"attributes": {"displayName": "Test User 1"}, "data": {"test_key": "test_value"}},
                },
                "linked_accounts": [],
            },
        }
        result = self._create_user(req)

        # Load the created user from the database, ensuring it was in fact created
        db_user = self.userdb.get_user_by_external_id(req["externalId"])
        self.assertIsNotNone(db_user, "Created user not found in the database")

        self._assertUserUpdateSuccess(result.request, result.response, db_user)

        # check that the action resulted in an event in the database
        events = self.eventdb.get_events_by_resource(SCIMResourceType.USER, db_user.scim_id)
        assert len(events) == 1
        event = events[0]
        assert event.resource.external_id == req["externalId"]
        assert event.data["status"] == EventStatus.CREATED.value

    def test_create_and_update_user(self):
        """Test that creating a user and then updating it without changes only results in one event"""
        req = {
            "externalId": "test-id-1",
            "name": {"familyName": "Testsson", "givenName": "Test", "middleName": "Testaren"},
            "emails": [{"primary": True, "type": "home", "value": "test@example.com"}],
            "phoneNumbers": [{"primary": True, "type": "mobile", "value": "tel:+1-202-456-1414"}],
            "preferredLanguage": "en",
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {
                    "test": {"attributes": {"displayName": "Test User 1"}, "data": {"test_key": "test_value"}}
                },
            },
        }
        result1 = self._create_user(req)

        # check that the action resulted in an event in the database
        events1 = self.eventdb.get_events_by_resource(SCIMResourceType.USER, result1.parsed_response.id)
        assert len(events1) == 1
        event = events1[0]
        assert event.resource.external_id == req["externalId"]
        assert event.data["status"] == EventStatus.CREATED.value

        # Update the user without making any changes
        result2 = self._update_user(req, result1.parsed_response.id, result1.parsed_response.meta.version)
        # Make sure the version wasn't updated
        assert result1.parsed_response.meta.version == result2.parsed_response.meta.version
        # Make sure no additional event was created
        events2 = self.eventdb.get_events_by_resource(SCIMResourceType.USER, result2.parsed_response.id)
        assert len(events2) == 1
        assert events1 == events2

    def test_create_user_no_external_id(self):
        req = {
            "schemas": [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {
                    "test": {"attributes": {"displayName": "Test User 1"}, "data": {"test_key": "test_value"}},
                },
                "linked_accounts": [],
            },
        }
        response = self.client.post(url="/Users/", json=req, headers=self.headers)
        self._assertResponse(response, status_code=201)

        # Load the created user from the database, ensuring it was in fact created
        db_user = self.userdb.get_user_by_scim_id(response.json()["id"])
        self.assertIsNotNone(db_user, "Created user not found in the database")

        self._assertUserUpdateSuccess(req, response, db_user)

    def test_create_user_duplicated_external_id(self):
        external_id = "test-id-1"
        # Create an existing user in the db
        self.add_user(identifier=str(uuid4()), external_id=external_id, profiles={"test": self.test_profile})
        # Try to create a new user with the same external_id
        req = {
            "schemas": [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
            "externalId": external_id,
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {"test": {"attributes": {"displayName": "Test User 2"}, "data": {"test_key": "test_value"}}}
            },
        }
        response = self.client.post(url="/Users/", json=req, headers=self.headers)
        self._assertScimError(
            response.json(), schemas=["urn:ietf:params:scim:api:messages:2.0:Error"], detail="externalID must be unique"
        )

    def test_update_user(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id="test-id-1", profiles={"test": self.test_profile})
        req = {
            "schemas": [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
            "id": str(db_user.scim_id),
            "externalId": "test-id-1",
            "name": {"familyName": "Testsson", "givenName": "Test", "middleName": "Testaren"},
            "emails": [{"primary": True, "type": "home", "value": "test@example.com"}],
            "phoneNumbers": [{"primary": True, "type": "mobile", "value": "tel:+1-202-456-1414"}],
            "preferredLanguage": "en",
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {
                    "test": {"attributes": {"displayName": "New display name"}, "data": {"test_key": "new value"}}
                },
                "linked_accounts": [],
            },
        }
        self.headers["IF-MATCH"] = make_etag(db_user.version)
        response = self.client.put(url=f"/Users/{db_user.scim_id}", json=req, headers=self.headers)
        self._assertResponse(response)
        db_user = self.userdb.get_user_by_scim_id(response.json()["id"])
        self._assertUserUpdateSuccess(req, response, db_user)

        # check that the action resulted in an event in the database
        events = self.eventdb.get_events_by_resource(SCIMResourceType.USER, db_user.scim_id)
        assert len(events) == 1
        event = events[0]
        assert event.resource.external_id == req["externalId"]
        assert event.data["status"] == EventStatus.UPDATED.value

    def test_update_user_change_properties(self):
        # Create the user
        req = {
            "schemas": [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
            "externalId": "test-id-1",
            "name": {"familyName": "Testsson", "givenName": "Test", "middleName": "Testaren"},
            "emails": [{"primary": True, "type": "home", "value": "test@example.com"}],
            "phoneNumbers": [{"primary": True, "type": "mobile", "value": "tel:+1-202-456-1414"}],
            "preferredLanguage": "en",
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {
                    "test": {"attributes": {"displayName": "Test User 1"}, "data": {"test_key": "test_value"}}
                },
                "linked_accounts": [],
            },
        }
        create_response = self.client.post(url="/Users/", json=req, headers=self.headers)
        self._assertResponse(create_response, status_code=201)

        # Update the user
        req = {
            "schemas": [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
            "id": create_response.json()["id"],
            "externalId": "test-id-1",
            "name": {"familyName": "Testsson", "givenName": "Test", "middleName": "T"},
            "emails": [{"primary": True, "type": "home", "value": "test2@example.com"}],
            "phoneNumbers": [{"primary": True, "type": "mobile", "value": "tel:+5-555-555"}],
            "preferredLanguage": "sv-SE",
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {
                    "test": {
                        "attributes": {"displayName": "Another display name"},
                        "data": {"test_key": "another value"},
                    },
                },
                "linked_accounts": [],
            },
        }
        self.headers["IF-MATCH"] = create_response.headers["etag"]
        response = self.client.put(url=f'/Users/{create_response.json()["id"]}', json=req, headers=self.headers)
        self._assertResponse(response)

        db_user = self.userdb.get_user_by_scim_id(response.json()["id"])
        self._assertUserUpdateSuccess(req, response, db_user)

    def test_update_user_set_external_id(self):
        db_user = self.add_user(identifier=str(uuid4()), profiles={"test": self.test_profile})
        req = {
            "schemas": [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
            "id": str(db_user.scim_id),
            "externalId": "test-id-1",
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {
                    "test": {"attributes": {"displayName": "New display name"}, "data": {"test_key": "new value"}}
                },
                "linked_accounts": [],
            },
        }
        self.headers["IF-MATCH"] = make_etag(db_user.version)
        response = self.client.put(url=f"/Users/{db_user.scim_id}", json=req, headers=self.headers)
        self._assertResponse(response)
        db_user = self.userdb.get_user_by_scim_id(response.json()["id"])
        self._assertUserUpdateSuccess(req, response, db_user)

    def test_update_user_duplicated_external_id(self):
        external_id = "test-id-1"
        # Create two existing users with different external_id
        self.add_user(identifier=str(uuid4()), external_id=external_id, profiles={"test": self.test_profile})
        db_user = self.add_user(identifier=str(uuid4()), external_id="test-id-2", profiles={"test": self.test_profile})
        # Try to update the second user with the external_id of the first
        req = {
            "schemas": [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
            "id": str(db_user.scim_id),
            "externalId": external_id,
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {
                    "test": {"attributes": {"displayName": "New display name"}, "data": {"test_key": "new value"}}
                }
            },
        }
        self.headers["IF-MATCH"] = make_etag(db_user.version)
        response = self.client.put(url=f"/Users/{db_user.scim_id}", json=req, headers=self.headers)
        self._assertScimError(
            response.json(), schemas=["urn:ietf:params:scim:api:messages:2.0:Error"], detail="externalID must be unique"
        )

    def test_search_user_external_id(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id="test-id-1", profiles={"test": self.test_profile})
        self.add_user(identifier=str(uuid4()), external_id="test-id-2", profiles={"test": self.test_profile})
        self._perform_search(search_filter=f'externalId eq "{db_user.external_id}"', expected_user=db_user)

    def test_search_user_last_modified(self):
        db_user1 = self.add_user(identifier=str(uuid4()), external_id="test-id-1", profiles={"test": self.test_profile})
        db_user2 = self.add_user(identifier=str(uuid4()), external_id="test-id-2", profiles={"test": self.test_profile})
        self.assertGreater(db_user2.last_modified, db_user1.last_modified)

        self._perform_search(
            search_filter=f'meta.lastModified ge "{db_user1.last_modified.isoformat()}"',
            expected_num_resources=2,
            expected_total_results=2,
        )

        self._perform_search(
            search_filter=f'meta.lastModified gt "{db_user1.last_modified.isoformat()}"', expected_user=db_user2
        )

    def test_search_user_profile_data(self):
        db_user = self.add_user(identifier=str(uuid4()), external_id="test-id-1", profiles={"test": self.test_profile})
        self.add_user(identifier=str(uuid4()), external_id="test-id-2", profiles={"test": self.test_profile2})
        self._perform_search(search_filter='profiles.test.data.test_key eq "test_value"', expected_user=db_user)

    def test_search_user_start_index(self):
        for i in range(9):
            self.add_user(identifier=str(uuid4()), external_id=f"test-id-{i}", profiles={"test": self.test_profile})
        self.assertEqual(9, self.userdb.db_count())
        last_modified = datetime.utcnow() - timedelta(hours=1)
        self._perform_search(
            search_filter=f'meta.lastmodified gt "{last_modified.isoformat()}"',
            start=5,
            return_json=True,
            expected_num_resources=5,
            expected_total_results=9,
        )

    def test_search_user_count(self):
        for i in range(9):
            self.add_user(identifier=str(uuid4()), external_id=f"test-id-{i}", profiles={"test": self.test_profile})
        self.assertEqual(9, self.userdb.db_count())
        last_modified = datetime.utcnow() - timedelta(hours=1)
        self._perform_search(
            search_filter=f'meta.lastmodified gt "{last_modified.isoformat()}"',
            count=5,
            return_json=True,
            expected_num_resources=5,
            expected_total_results=9,
        )

    def test_search_user_start_index_and_count(self):
        for i in range(9):
            self.add_user(identifier=str(uuid4()), external_id=f"test-id-{i}", profiles={"test": self.test_profile})
        self.assertEqual(9, self.userdb.db_count())
        last_modified = datetime.utcnow() - timedelta(hours=1)
        self._perform_search(
            search_filter=f'meta.lastmodified gt "{last_modified.isoformat()}"',
            start=7,
            count=5,
            return_json=True,
            expected_num_resources=3,
            expected_total_results=9,
        )

    def test_create_and_update_user_with_linked_accounts(self):
        """Test that creating a user and then updating it without changes only results in one event"""
        account = LinkedAccount(issuer="eduid.se", value="test@dev.eduid.se")
        _db_account = ScimApiLinkedAccount(issuer=account.issuer, value=account.value, parameters=account.parameters)
        req = {
            SCIMSchema.NUTID_USER_V1.value: {"profiles": {}, "linked_accounts": [account.to_dict()]},
        }
        result1 = self._create_user(req)

        self._assertResponse(result1.response, status_code=201)
        db_user = self.userdb.get_user_by_scim_id(str(result1.parsed_response.id))
        assert db_user
        self._assertUserUpdateSuccess(req, result1.response, db_user)

        # Verify that the linked account was stored in the database
        assert db_user.linked_accounts == [_db_account]

        # Add mfa_stepup parameter
        account.parameters["mfa_stepup"] = True
        _db_account.parameters["mfa_stepup"] = True
        req[SCIMSchema.NUTID_USER_V1.value]["linked_accounts"] = [account.to_dict()]

        # Update the user
        result2 = self._update_user(req, result1.parsed_response.id, result1.parsed_response.meta.version)
        self._assertResponse(result2.response, status_code=200)
        db_user = self.userdb.get_user_by_scim_id(str(result2.parsed_response.id))
        assert db_user
        self._assertUserUpdateSuccess(req, result2.response, db_user)

        # Make sure the version was updated
        assert result1.parsed_response.meta.version != result2.parsed_response.meta.version

        # Verify the updated account made it into the database
        assert db_user.linked_accounts == [_db_account]

    def test_create_user_with_invalid_linked_accounts_issuer(self):
        """Test that creating a user with an invalid issuer and valid value fails"""
        account = LinkedAccount(issuer="NOT-eduid.se", value="test@dev.eduid.se")
        req = {
            "externalId": "test-id-9",
            "name": {"familyName": "Testsson", "givenName": "Test", "middleName": "Testaren"},
            SCIMSchema.NUTID_USER_V1.value: {"profiles": {}, "linked_accounts": [account.dict(exclude_none=True)]},
        }
        result1 = self._create_user(req, expect_success=False)
        self._assertScimError(json=result1.response.json(), detail="Invalid nutid linked_accounts")

    def test_create_user_with_invalid_linked_accounts_value(self):
        """Test that creating a user with valid issuer and invalid value fails"""
        account = LinkedAccount(issuer="eduid.se", value="test@eduid.com")
        req = {
            "externalId": "test-id-9",
            "name": {"familyName": "Testsson", "givenName": "Test", "middleName": "Testaren"},
            SCIMSchema.NUTID_USER_V1.value: {"profiles": {}, "linked_accounts": [account.dict(exclude_none=True)]},
        }
        result1 = self._create_user(req, expect_success=False)
        self._assertScimError(json=result1.response.json(), detail="Invalid nutid linked_accounts")

    def test_update_user_set_linked_accounts(self):
        db_account1 = ScimApiLinkedAccount(issuer="eduid.se", value="test1@dev.eduid.se")
        account2 = LinkedAccount(issuer="eduid.se", value="test2@eduid.se", parameters={"mfa_stepup": True})
        db_user = self.add_user(identifier=str(uuid4()), linked_accounts=[db_account1])
        req = {
            "schemas": [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
            "id": str(db_user.scim_id),
            SCIMSchema.NUTID_USER_V1.value: {"profiles": {}, "linked_accounts": [account2.to_dict()]},
        }
        result = self._update_user(req, db_user.scim_id, version=db_user.version)
        self._assertResponse(result.response)
        self._assertUserUpdateSuccess(req, result.response, db_user)

    def test_update_user_set_linked_accounts2(self):
        """Test updating linked accounts sorted 'wrong'"""
        db_account1 = ScimApiLinkedAccount(issuer="eduid.se", value="test1@dev.eduid.se")
        account1 = LinkedAccount(issuer=db_account1.issuer, value=db_account1.value)
        account2 = LinkedAccount(issuer="eduid.se", value="test2@eduid.se", parameters={"mfa_stepup": True})
        db_user = self.add_user(identifier=str(uuid4()), linked_accounts=[db_account1])
        req = {
            "schemas": [SCIMSchema.CORE_20_USER.value, SCIMSchema.NUTID_USER_V1.value],
            "id": str(db_user.scim_id),
            SCIMSchema.NUTID_USER_V1.value: {
                "profiles": {},
                "linked_accounts": [account2.to_dict(), account1.to_dict()],
            },
        }
        result = self._update_user(req, db_user.scim_id, version=db_user.version)
        self._assertResponse(result.response)
        self._assertUserUpdateSuccess(req, result.response, db_user)
        db_user = self.userdb.get_user_by_scim_id(str(db_user.scim_id))
        assert db_user
        db_account2 = ScimApiLinkedAccount(issuer=account2.issuer, value=account2.value, parameters=account2.parameters)
        assert db_user.linked_accounts == [db_account2, db_account1]

    def _perform_search(
        self,
        search_filter: str,
        start: int = 1,
        count: int = 10,
        return_json: bool = False,
        expected_user: Optional[ScimApiUser] = None,
        expected_num_resources: Optional[int] = None,
        expected_total_results: Optional[int] = None,
    ):
        logger.info(f"Searching for user(s) using filter {repr(search_filter)}")
        req = {
            "schemas": [SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST.value],
            "filter": search_filter,
            "startIndex": start,
            "count": count,
        }
        response = self.client.post(url="/Users/.search", json=req, headers=self.headers)
        logger.info(f"Search parsed_response:\n{response.json}")
        if return_json:
            return response.json
        self._assertResponse(response)
        expected_schemas = [SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value]
        response_schemas = response.json().get("schemas")
        self.assertIsInstance(response_schemas, list, "Response schemas not present, or not a list")
        self.assertEqual(
            sorted(set(expected_schemas)),
            sorted(set(response_schemas)),
            "Unexpected schema(s) in search parsed_response",
        )

        resources = response.json().get("Resources")

        if expected_user is not None:
            expected_num_resources = 1
            expected_total_results = 1

        if expected_num_resources is not None:
            self.assertEqual(
                expected_num_resources,
                len(resources),
                f"Number of resources returned expected to be {expected_num_resources}",
            )
            if expected_total_results is None:
                expected_total_results = expected_num_resources
        if expected_total_results is not None:
            self.assertEqual(
                expected_total_results,
                response.json().get("totalResults"),
                f"Response totalResults expected to be {expected_total_results}",
            )

        if expected_user is not None:
            self.assertEqual(
                str(expected_user.scim_id),
                resources[0].get("id"),
                f"Search parsed_response user does not have the expected id: {str(expected_user.scim_id)}",
            )

        self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], response.json().get("schemas"))
        resources = response.json().get("Resources")
        return resources
