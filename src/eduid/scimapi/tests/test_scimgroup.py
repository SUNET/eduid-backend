__author__ = "lundberg"

import logging
from collections.abc import Mapping
from typing import Any
from uuid import UUID, uuid4

from bson import ObjectId
from httpx import Response

from eduid.common.config.base import DataOwnerName
from eduid.common.misc.timeutil import utc_now
from eduid.common.models.scim_base import Meta, SCIMResourceType, SCIMSchema, WeakVersion
from eduid.common.testing_base import normalised_data
from eduid.common.utils import make_etag
from eduid.graphdb.groupdb import Group as GraphGroup
from eduid.graphdb.groupdb import User as GraphUser
from eduid.scimapi.models.group import GroupMember, GroupResponse
from eduid.scimapi.testing import ScimApiTestCase
from eduid.scimapi.tests.test_scimbase import TestScimBase
from eduid.userdb.scimapi import EventStatus, GroupExtensions, ScimApiGroup
from eduid.userdb.scimapi.userdb import ScimApiUser

logger = logging.getLogger(__name__)


class TestSCIMGroup(TestScimBase):
    def setUp(self) -> None:
        self.meta = Meta(
            location="http://example.org/Groups/some-id",
            resource_type=SCIMResourceType.GROUP,
            created=utc_now(),
            last_modified=utc_now(),
            version=WeakVersion(),
        )

    def test_group(self) -> None:
        group = GroupResponse(id=uuid4(), schemas=[SCIMSchema.CORE_20_GROUP], meta=self.meta, display_name="Test Group")
        member_1_id = uuid4()
        member_2_id = uuid4()
        group.members.extend(
            [
                GroupMember(value=member_1_id, display="Member 1", ref=f"https://some_domain/path/Users/{member_1_id}"),
                GroupMember(
                    value=member_2_id, display="Member 2", ref=f"https://some_domain/path/Groups/{member_2_id}"
                ),
            ]
        )
        group_dump = group.json(exclude_none=True)
        loaded_group = GroupResponse.parse_raw(group_dump)
        assert normalised_data(group.dict(exclude_none=True)) == normalised_data(loaded_group.dict(exclude_none=True))


class TestGroupResource(ScimApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.groupdb = self.context.get_groupdb(DataOwnerName("eduid.se"))

    def tearDown(self) -> None:
        super().tearDown()
        assert self.groupdb
        self.groupdb._drop_whole_collection()

    def add_group(self, scim_id: UUID, display_name: str, extensions: GroupExtensions | None = None) -> ScimApiGroup:
        if extensions is None:
            extensions = GroupExtensions()
        group = ScimApiGroup(scim_id=scim_id, display_name=display_name, extensions=extensions)
        assert self.groupdb  # mypy doesn't know setUp will be called
        group.graph = GraphGroup(identifier=str(group.scim_id), display_name=display_name)
        self.groupdb.save(group)
        return group

    def add_member(self, group: ScimApiGroup, member: ScimApiUser | ScimApiGroup, display_name: str) -> ScimApiGroup:
        if isinstance(member, ScimApiUser):
            user_member = GraphUser(identifier=str(member.scim_id), display_name=display_name)
            group.add_member(user_member)
        elif isinstance(member, ScimApiGroup):
            group_member = GraphGroup(identifier=str(member.scim_id), display_name=display_name)
            group.add_member(group_member)
        assert self.groupdb  # mypy doesn't know setUp will be called
        self.groupdb.save(group)
        return group

    def _perform_search(
        self,
        filter: str,
        start: int = 1,
        count: int = 10,
        return_json: bool = False,
        expected_group: ScimApiGroup | None = None,
        expected_num_resources: int | None = None,
        expected_total_results: int | None = None,
    ) -> dict:
        logger.info(f"Searching for group(s) using filter {repr(filter)}")
        req = {
            "schemas": [SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST.value],
            "filter": filter,
            "startIndex": start,
            "count": count,
        }
        response = self.client.post(url="/Groups/.search", json=req, headers=self.headers)
        logger.info(f"Search parsed_response:\n{response.json}")
        if return_json:
            return response.json()

        expected_schemas = [SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value]
        response_schemas = response.json().get("schemas")
        self.assertIsInstance(response_schemas, list, "Response schemas not present, or not a list")
        self.assertEqual(
            sorted(set(expected_schemas)),
            sorted(set(response_schemas)),
            "Unexpected schema(s) in search parsed_response",
        )

        resources = response.json().get("Resources")
        if expected_group is not None:
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

        if expected_group is not None:
            self.assertEqual(
                str(expected_group.scim_id),
                resources[0].get("id"),
                f"Search parsed_response group does not have the expected id: {str(expected_group.scim_id)}",
            )
            self.assertEqual(
                expected_group.display_name,
                resources[0].get("displayName"),
                "Search parsed_response group does not have the expected displayName: "
                f"{str(expected_group.display_name)}",
            )

        return resources

    def _assertGroupUpdateSuccess(self, req: Mapping, response: Response, group: ScimApiGroup) -> None:
        """Function to validate successful responses to SCIM calls that update a group according to a request."""
        if response.json().get("schemas") == [SCIMSchema.ERROR.value]:
            self.fail(f"Got SCIM error parsed_response ({response.status_code}):\n{response.json}")

        expected_schemas = req.get("schemas", [SCIMSchema.CORE_20_GROUP.value])
        if (
            SCIMSchema.NUTID_GROUP_V1.value in response.json()
            and SCIMSchema.NUTID_GROUP_V1.value not in expected_schemas
        ):
            # The API can always add this extension to the parsed_response, even if it was not in the request
            expected_schemas += [SCIMSchema.NUTID_GROUP_V1.value]

        self._assertScimResponseProperties(response, resource=group, expected_schemas=expected_schemas)

        # Validate group update specifics
        self.assertEqual(
            group.display_name, response.json().get("displayName"), "Incorrect displayName in parsed_response"
        )
        self.assertEqual(
            group.external_id, response.json().get("externalId"), "Incorrect externalId in parsed_response"
        )
        request_members = _members_to_set(req["members"])
        self.assertEqual(
            request_members, _members_to_set(response.json().get("members")), "Incorrect members in parsed_response"
        )

        if SCIMSchema.NUTID_GROUP_V1.value in req:
            self.assertEqual(
                req[SCIMSchema.NUTID_GROUP_V1.value],
                response.json().get(SCIMSchema.NUTID_GROUP_V1.value),
                "Unexpected NUTID group data in parsed_response",
            )


class TestGroupResource_GET(TestGroupResource):
    def test_get_groups(self) -> None:
        for i in range(9):
            self.add_group(uuid4(), f"Test Group {i}")
        response = self.client.get(url="/Groups", headers=self.headers)
        self.assertEqual([SCIMSchema.API_MESSAGES_20_LIST_RESPONSE.value], response.json().get("schemas"))
        resources = response.json().get("Resources")
        assert self.groupdb
        expected_num_resources = self.groupdb.graphdb.db.count_nodes()
        self.assertEqual(
            expected_num_resources,
            len(resources),
            f"Number of groups returned does not match number of groups in the database: {expected_num_resources}",
        )
        self.assertEqual(
            expected_num_resources,
            response.json().get("totalResults"),
            f"Response totalResults does not match number of groups in the database: {expected_num_resources}",
        )

    def test_get_group(self) -> None:
        db_group = self.add_group(uuid4(), "Test Group 1")
        response = self.client.get(url=f"/Groups/{db_group.scim_id}", headers=self.headers)
        self._assertGroupUpdateSuccess({"members": []}, response, db_group)

    def test_get_group_not_found(self) -> None:
        response = self.client.get(url=f"/Groups/{uuid4()}", headers=self.headers)
        self._assertScimError(response.json(), status=404, detail="Group not found")


class TestGroupResource_POST(TestGroupResource):
    def test_create_group(self) -> None:
        req = {
            "schemas": [SCIMSchema.CORE_20_GROUP.value],
            "displayName": "Test Group 1",
            "externalId": "a-group",
            "members": [],
        }
        response = self.client.post(url="/Groups/", json=req, headers=self.headers)

        # Load the created group from the database, ensuring it was in fact created
        assert self.groupdb
        assert isinstance(req["displayName"], str)  # please mypy
        _groups, _count = self.groupdb.get_groups_by_property("display_name", req["displayName"])
        self.assertEqual(1, _count, "More or less than one group found in the database after create")
        db_group = _groups[0]

        self._assertGroupUpdateSuccess(req, response, db_group)

        # check that the action resulted in an event in the database
        assert self.eventdb
        events = self.eventdb.get_events_by_resource(SCIMResourceType.GROUP, db_group.scim_id)
        assert len(events) == 1
        event = events[0]
        assert event.resource.external_id == req["externalId"]
        assert event.data["status"] == EventStatus.CREATED.value

    def test_schema_violation(self) -> None:
        # request missing displayName
        req = {"schemas": [SCIMSchema.CORE_20_GROUP.value], "members": []}
        response = self.client.post(url="/Groups/", json=req, headers=self.headers)
        self._assertScimError(
            status=422,
            json=response.json(),
            detail=[
                {
                    "type": "missing",
                    "loc": ["body", "displayName"],
                    "msg": "Field required",
                }
            ],
            exclude_keys=["input", "url"],
        )


class TestGroupResource_PUT(TestGroupResource):
    def test_update_group(self) -> None:
        db_group = self.add_group(uuid4(), "Test Group 1")
        subgroup = self.add_group(uuid4(), "Test Group 2")
        user = self.add_user(identifier=str(uuid4()), external_id="not-used")
        members = [
            {
                "value": str(user.scim_id),
                "$ref": f"http://localhost:8000/Users/{user.scim_id}",
                "display": "Test User 1",
            },
            {
                "value": str(subgroup.scim_id),
                "$ref": f"http://localhost:8000/Groups/{subgroup.scim_id}",
                "display": "Test Group 2",
            },
        ]
        req = {
            "schemas": [SCIMSchema.CORE_20_GROUP.value],
            "id": str(db_group.scim_id),
            "displayName": db_group.display_name,
            "members": members,
        }
        self.headers["IF-MATCH"] = make_etag(db_group.version)
        response = self.client.put(url=f"/Groups/{db_group.scim_id}", json=req, headers=self.headers)

        self._assertGroupUpdateSuccess(req, response, db_group)

    def test_update_existing_group(self) -> None:
        db_group = self.add_group(uuid4(), "Test Group 1")
        subgroup = self.add_group(uuid4(), "Test Group 2")
        user = self.add_user(identifier=str(uuid4()), external_id="not-used")
        members = [
            {
                "value": str(user.scim_id),
                "$ref": f"http://localhost:8000/Users/{user.scim_id}",
                "display": "Test User 1",
            },
            {
                "value": str(subgroup.scim_id),
                "$ref": f"http://localhost:8000/Groups/{subgroup.scim_id}",
                "display": "Test Group 2",
            },
        ]
        db_group.display_name = "Another display name"
        db_group.external_id = "external id"
        req = {
            "schemas": [SCIMSchema.CORE_20_GROUP.value, SCIMSchema.NUTID_GROUP_V1.value],
            "id": str(db_group.scim_id),
            "externalId": db_group.external_id,
            "displayName": db_group.display_name,
            "members": members,
            SCIMSchema.NUTID_GROUP_V1.value: {"data": {"test": "updated"}},
        }
        self.headers["IF-MATCH"] = make_etag(db_group.version)
        response = self.client.put(url=f"/Groups/{db_group.scim_id}", json=req, headers=self.headers)

        self._assertGroupUpdateSuccess(req, response, db_group)

        members[0]["display"] += " (updated)"
        members[1]["display"] += " (also updated)"

        self.headers["IF-MATCH"] = response.headers["Etag"]
        response = self.client.put(url=f"/Groups/{db_group.scim_id}", json=req, headers=self.headers)
        self._assertGroupUpdateSuccess(req, response, db_group)

        # check that the action resulted in an event in the database
        assert self.eventdb
        events = self.eventdb.get_events_by_resource(SCIMResourceType.GROUP, db_group.scim_id)
        assert len(events) == 2
        event = events[0]
        assert event.resource.external_id == req["externalId"]
        assert event.data["status"] == EventStatus.UPDATED.value

    def test_add_member_to_existing_group(self) -> None:
        db_group = self.add_group(uuid4(), "Test Group 1")
        user = self.add_user(identifier=str(uuid4()), external_id="not-used")
        members = [
            {
                "value": str(user.scim_id),
                "$ref": f"http://localhost:8000/Users/{user.scim_id}",
                "display": "Test User 1",
            }
        ]
        req = {
            "schemas": [SCIMSchema.CORE_20_GROUP.value],
            "id": str(db_group.scim_id),
            "displayName": db_group.display_name,
            "members": members,
        }
        self.headers["IF-MATCH"] = make_etag(db_group.version)
        response = self.client.put(url=f"/Groups/{db_group.scim_id}", json=req, headers=self.headers)

        self._assertGroupUpdateSuccess(req, response, db_group)

        # Now, add another user and make a new request

        added_user = self.add_user(identifier=str(uuid4()), external_id="not-used-2")
        members += [
            {
                "value": str(added_user.scim_id),
                "$ref": f"http://localhost:8000/Users/{added_user.scim_id}",
                "display": "Added User",
            }
        ]

        self.headers["IF-MATCH"] = response.headers["Etag"]
        response = self.client.put(url=f"/Groups/{db_group.scim_id}", json=req, headers=self.headers)
        self._assertGroupUpdateSuccess(req, response, db_group)

    def test_removing_group_member(self) -> None:
        db_group = self.add_group(uuid4(), "Test Group 1")
        subgroup = self.add_group(uuid4(), "Test Group 2")
        db_group = self.add_member(db_group, subgroup, "Test User")
        user = self.add_user(identifier=str(uuid4()), external_id="not-used")
        db_group = self.add_member(db_group, user, "Test User")

        assert self.groupdb

        # Load group to verify it has two members
        _g1 = self.groupdb.get_group_by_scim_id(str(db_group.scim_id))
        assert _g1
        self.assertEqual(2, len(_g1.graph.members), "Group loaded from database does not have two members")
        self.assertEqual(1, len(_g1.graph.member_users), "Group loaded from database does not have one member user")
        self.assertEqual(1, len(_g1.graph.member_groups), "Group loaded from database does not have one member group")

        members = [
            {
                "value": str(user.scim_id),
                "$ref": f"http://localhost:8000/Users/{user.scim_id}",
                "display": "Test User 1",
            },
        ]
        req = {
            "schemas": [SCIMSchema.CORE_20_GROUP.value, SCIMSchema.NUTID_GROUP_V1.value],
            "id": str(db_group.scim_id),
            "displayName": db_group.display_name,
            "members": members,
            SCIMSchema.NUTID_GROUP_V1.value: {"data": {"test": "updated"}},
        }

        self.headers["IF-MATCH"] = make_etag(db_group.version)
        response = self.client.put(url=f"/Groups/{db_group.scim_id}", json=req, headers=self.headers)

        self._assertGroupUpdateSuccess(req, response, db_group)

        # Load group to verify it has one less member now
        _g2 = self.groupdb.get_group_by_scim_id(str(db_group.scim_id))
        assert _g2
        self.assertEqual(1, len(_g2.graph.members), "Group loaded from database does not have two members")
        self.assertEqual(1, len(_g2.graph.member_users), "Group loaded from database does not have one member user")
        self.assertEqual(0, len(_g2.graph.member_groups), "Group loaded from database does not have one member group")

    def test_update_group_id_mismatch(self) -> None:
        db_group = self.add_group(uuid4(), "Test Group 1")
        req = {
            "schemas": [SCIMSchema.CORE_20_GROUP.value],
            "id": str(uuid4()),
            "displayName": "Another display name",
            "members": [],
        }
        response = self.client.put(url=f"/Groups/{db_group.scim_id}", json=req, headers=self.headers)
        self._assertScimError(response.json(), detail="Id mismatch")

    def test_update_group_not_found(self) -> None:
        req = {
            "schemas": [SCIMSchema.CORE_20_GROUP.value],
            "id": str(uuid4()),
            "displayName": "Another display name",
            "members": [],
        }
        response = self.client.put(url=f'/Groups/{req["id"]}', json=req, headers=self.headers)
        self._assertScimError(response.json(), status=404, detail="Group not found")

    def test_version_mismatch(self) -> None:
        db_group = self.add_group(uuid4(), "Test Group 1")
        req = {
            "schemas": [SCIMSchema.CORE_20_GROUP.value],
            "id": str(db_group.scim_id),
            "displayName": "Another display name",
        }
        self.headers["IF-MATCH"] = make_etag(ObjectId())
        response = self.client.put(url=f"/Groups/{db_group.scim_id}", json=req, headers=self.headers)
        self._assertScimError(response.json(), detail="Version mismatch")

    def test_update_group_member_does_not_exist(self) -> None:
        db_group = self.add_group(uuid4(), "Test Group 1")
        _user_scim_id = str(uuid4())
        members = [
            {
                "value": _user_scim_id,
                "$ref": f"http://localhost:8000/Users/{_user_scim_id}",
                "display": "Test User 1",
            }
        ]
        req = {
            "schemas": [SCIMSchema.CORE_20_GROUP.value],
            "id": str(db_group.scim_id),
            "displayName": "Another display name",
            "members": members,
        }
        self.headers["IF-MATCH"] = make_etag(db_group.version)
        response = self.client.put(url=f"/Groups/{db_group.scim_id}", json=req, headers=self.headers)
        self._assertScimError(response.json(), detail=f"User {_user_scim_id} not found")

    def test_update_group_subgroup_does_not_exist(self) -> None:
        db_group = self.add_group(uuid4(), "Test Group 1")
        _subgroup_scim_id = str(uuid4())
        members = [
            {
                "value": _subgroup_scim_id,
                "$ref": f"http://localhost:8000/Groups/{_subgroup_scim_id}",
                "display": "Test Group 2",
            }
        ]
        req = {
            "schemas": [SCIMSchema.CORE_20_GROUP.value],
            "id": str(db_group.scim_id),
            "displayName": "Another display name",
            "members": members,
        }
        self.headers["IF-MATCH"] = make_etag(db_group.version)
        response = self.client.put(url=f"/Groups/{db_group.scim_id}", json=req, headers=self.headers)
        self._assertScimError(response.json(), detail=f"Group {_subgroup_scim_id} not found")

    def test_schema_violation(self) -> None:
        # request missing displayName
        req = {
            "schemas": [SCIMSchema.CORE_20_GROUP.value],
            "id": str(uuid4()),
        }
        response = self.client.put(url=f"/Groups/{uuid4()}", json=req, headers=self.headers)
        self._assertScimError(
            status=422,
            json=response.json(),
            detail=[
                {
                    "loc": ["body", "displayName"],
                    "msg": "Field required",
                    "type": "missing",
                }
            ],
            exclude_keys=["input", "url"],
        )


class TestGroupResource_DELETE(TestGroupResource):
    def test_delete_group(self) -> None:
        group = self.add_group(uuid4(), "Test Group 1")
        assert self.groupdb
        assert self.eventdb

        # Verify we can find the group in the database
        db_group1 = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert db_group1 is not None

        self.headers["IF-MATCH"] = make_etag(group.version)
        response = self.client.delete(url=f"/Groups/{group.scim_id}", headers=self.headers)
        self.assertEqual(204, response.status_code)

        # Verify the group is no longer in the database
        db_group2 = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert db_group2 is None

        # check that the action resulted in an event in the database
        events = self.eventdb.get_events_by_resource(SCIMResourceType.GROUP, db_group1.scim_id)
        assert len(events) == 1
        event = events[0]
        assert event.resource.external_id is None
        assert event.data["status"] == EventStatus.DELETED.value

    def test_version_mismatch(self) -> None:
        group = self.add_group(uuid4(), "Test Group 1")

        self.headers["IF-MATCH"] = make_etag(ObjectId())
        response = self.client.delete(url=f"/Groups/{group.scim_id}", headers=self.headers)
        self._assertScimError(response.json(), detail="Version mismatch")

    def test_group_not_found(self) -> None:
        response = self.client.delete(url=f"/Groups/{uuid4()}", headers=self.headers)
        self._assertScimError(response.json(), status=404, detail="Group not found")


class TestGroupSearchResource(TestGroupResource):
    def test_search_group_display_name(self) -> None:
        db_group = self.add_group(uuid4(), "Test Group 1")
        self.add_group(uuid4(), "Test Group 2")
        self._perform_search(filter='displayName eq "Test Group 1"', expected_group=db_group)

    def test_search_group_display_name_not_found(self) -> None:
        self._perform_search(filter='displayName eq "Test No Such Group"', expected_total_results=0)

    def test_search_group_display_name_bad_operator(self) -> None:
        json = self._perform_search(filter="displayName lt 1", return_json=True)
        self._assertScimError(json, scim_type="invalidFilter", detail="Unsupported operator")

    def test_search_group_display_name_not_string(self) -> None:
        json = self._perform_search(filter="displayName eq 1", return_json=True)
        self._assertScimError(json, scim_type="invalidFilter", detail="Invalid displayName")

    def test_search_group_unknown_attribute(self) -> None:
        json = self._perform_search(filter="no_such_attribute lt 1", return_json=True)
        self._assertScimError(json, scim_type="invalidFilter", detail="Can't filter on attribute no_such_attribute")

    def test_search_group_start_index(self) -> None:
        for i in range(9):
            self.add_group(uuid4(), "Test Group")
        self._perform_search(
            filter='displayName eq "Test Group"', start=5, expected_num_resources=5, expected_total_results=9
        )

    def test_search_group_count(self) -> None:
        for i in range(9):
            self.add_group(uuid4(), "Test Group")

        assert self.groupdb
        groups = self.groupdb.get_groups()
        self.assertEqual(len(groups), 9)

        self._perform_search(
            filter='displayName eq "Test Group"', start=1, count=5, expected_num_resources=5, expected_total_results=9
        )

    def test_search_group_extension_data_attribute_str(self) -> None:
        ext = GroupExtensions(data={"some_key": "20072009"})
        db_group = self.add_group(uuid4(), "Test Group with extension", extensions=ext)

        self._perform_search(filter='extensions.data.some_key eq "20072009"', expected_group=db_group)

    def test_search_group_extension_data_bad_op(self) -> None:
        json = self._perform_search(filter='extensions.data.some_key XY "20072009"', return_json=True)
        self._assertScimError(json, detail="Unsupported operator")

    def test_search_group_extension_data_invalid_key(self) -> None:
        json = self._perform_search(filter='extensions.data.some.key eq "20072009"', return_json=True)
        self._assertScimError(json, detail="Unsupported extension search key")

    def test_search_group_extension_data_not_found(self) -> None:
        self._perform_search(filter='extensions.data.some_key eq "20072009"', expected_num_resources=0)

    def test_search_group_extension_data_attribute_int(self) -> None:
        ext1 = GroupExtensions(data={"some_key": 20072009})
        group = self.add_group(uuid4(), "Test Group with extension", extensions=ext1)

        # Add extra group that should not be matched by search
        ext2 = GroupExtensions(data={"some_key": 123})
        self.add_group(uuid4(), "Test Group with extension", extensions=ext2)

        self._perform_search(filter="extensions.data.some_key eq 20072009", expected_group=group)

    def test_search_group_last_modified(self) -> None:
        group1 = self.add_group(uuid4(), "Test Group 1")
        group2 = self.add_group(uuid4(), "Test Group 2")
        self.assertGreater(group2.last_modified, group1.last_modified)

        self._perform_search(
            filter=f'meta.lastModified ge "{group1.last_modified.isoformat()}"', expected_num_resources=2
        )

        self._perform_search(filter=f'meta.lastModified gt "{group1.last_modified.isoformat()}"', expected_group=group2)

    def test_search_group_last_modified_invalid_datetime_1(self) -> None:
        json = self._perform_search(filter="meta.lastModified ge 1", return_json=True)
        self._assertScimError(json, detail="Invalid datetime")

    def test_search_group_last_modified_invalid_datetime_2(self) -> None:
        json = self._perform_search(filter='meta.lastModified ge "2020-05-12_15:36:99+00:00"', return_json=True)
        self._assertScimError(json, detail="Invalid datetime")

    def test_schema_violation(self) -> None:
        # request missing filter
        req = {
            "schemas": [SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST.value],
        }
        response = self.client.post(url="/Groups/.search", json=req, headers=self.headers)
        self._assertScimError(
            status=422,
            json=response.json(),
            detail=[
                {
                    "loc": ["body", "filter"],
                    "msg": "Field required",
                    "type": "missing",
                }
            ],
            exclude_keys=["input", "url"],
        )


class TestGroupExtensionData(TestGroupResource):
    def test_nutid_extension(self) -> None:
        display_name = "Test Group with Nutid extension"
        nutid_data = {"data": {"testing": "certainly"}}
        req = {
            "schemas": [SCIMSchema.CORE_20_GROUP.value],
            "displayName": display_name,
            "members": [],
            SCIMSchema.NUTID_GROUP_V1.value: nutid_data,
        }
        post_resp = self.client.post(url="/Groups/", json=req, headers=self.headers)

        # Load the newly created group from the database in order to validate the SCIM parsed_response better
        scim_id = post_resp.json().get("id")
        self.assertIsNotNone(scim_id, "Group creation parsed_response id not present")
        assert self.groupdb
        db_group = self.groupdb.get_group_by_scim_id(scim_id)
        assert db_group
        expected_schemas = [SCIMSchema.CORE_20_GROUP.value, SCIMSchema.NUTID_GROUP_V1.value]
        self._assertScimResponseProperties(post_resp, db_group, expected_schemas=expected_schemas)
        self.assertEqual([], post_resp.json().get("members"), "Group was not expected to have members")

        # Verify NUTID data is part of the PUT parsed_response
        self.assertEqual(
            nutid_data,
            post_resp.json().get(SCIMSchema.NUTID_GROUP_V1.value),
            "Unexpected Nutid extension data in parsed_response",
        )

        # Now fetch the group and validate the data
        get_resp = self.client.get(url=f"/Groups/{scim_id}", headers=self.headers)
        self._assertScimResponseProperties(get_resp, db_group, expected_schemas=expected_schemas)
        self.assertEqual(
            post_resp.json(),
            get_resp.json(),
            "Group creation parsed_response should equal subsequent fetch parsed_response",
        )

        # And now, update the NUTID extension data
        nutid_data2 = {"data": {"testing": "yes", "other_key": 2}}
        req = {
            "schemas": [SCIMSchema.CORE_20_GROUP.value, SCIMSchema.NUTID_GROUP_V1.value],
            "id": str(scim_id),
            "displayName": display_name,
            "members": [],
            SCIMSchema.NUTID_GROUP_V1.value: nutid_data2,
        }
        self.headers["IF-MATCH"] = get_resp.json()["meta"]["version"]
        put_resp = self.client.put(url=f"/Groups/{scim_id}", json=req, headers=self.headers)
        self._assertScimResponseProperties(put_resp, db_group, expected_schemas=expected_schemas)

        # Now fetch the group again and validate the data
        get_resp2 = self.client.get(url=f"/Groups/{scim_id}", headers=self.headers)
        self.assertEqual(put_resp.json(), get_resp2.json())

        assert self.groupdb
        db_group = self.groupdb.get_group_by_scim_id(scim_id)
        assert db_group
        self._assertScimResponseProperties(get_resp2, db_group, expected_schemas=expected_schemas)
        self.assertEqual([], get_resp2.json().get("members"), "Group was not expected to have members")

        self.assertEqual(nutid_data2, get_resp2.json().get(SCIMSchema.NUTID_GROUP_V1.value))

        prev_meta = post_resp.json().get("meta")
        self.assertIsNotNone(prev_meta, "POST parsed_response has no meta section")
        meta = get_resp2.json().get("meta")
        self.assertIsNotNone(meta, "Second GET parsed_response has no meta section")
        self.assertEqual(meta["created"], prev_meta["created"], "meta.created was not expected to change")
        self.assertNotEqual(meta["lastModified"], prev_meta["lastModified"], "meta.lastModified not updated")
        self.assertNotEqual(meta["version"], prev_meta["version"], "meta.version not updated")


def _members_to_set(members: list[Mapping[str, Any]]) -> set[GroupMember]:
    res: set[GroupMember] = set()
    for this in members:
        res.add(GroupMember.from_mapping(this))
    return res
