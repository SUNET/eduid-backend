import json
from collections.abc import Mapping
from http import HTTPStatus
from typing import Any
from uuid import UUID

import pytest
from werkzeug.test import TestResponse

from eduid.common.testing_base import normalised_data
from eduid.graphdb.groupdb import User as GraphUser
from eduid.graphdb.testing import Neo4jTemporaryInstance
from eduid.userdb import User
from eduid.userdb.element import ElementKey
from eduid.userdb.scimapi import GroupExtensions, ScimApiGroup
from eduid.userdb.scimapi.userdb import ScimApiUser
from eduid.userdb.testing import SetupConfig
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.group_management.app import GroupManagementApp, init_group_management_app
from eduid.webapp.group_management.helpers import GroupManagementMsg
from eduid.webapp.group_management.schemas import GroupRole

__author__ = "lundberg"


class GroupManagementTests(EduidAPITestCase[GroupManagementApp]):
    """Base TestCase for those tests that need a full environment setup"""

    neo4j_instance: Neo4jTemporaryInstance
    neo4j_uri: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.neo4j_instance = Neo4jTemporaryInstance.get_instance(max_retry_seconds=60)
        cls.neo4j_uri = (
            f"bolt://{cls.neo4j_instance.DEFAULT_USERNAME}:{cls.neo4j_instance.DEFAULT_PASSWORD}"
            f"@localhost:{cls.neo4j_instance.bolt_port}"
        )
        super().setUpClass()

    def setUp(self, config: SetupConfig | None = None) -> None:
        users = ["hubba-bubba", "hubba-baar", "hubba-fooo"]
        if config is None:
            config = SetupConfig()
        config.users = users
        super().setUp(config=config)
        self.test_user2 = self.app.central_userdb.get_user_by_eppn("hubba-baar")
        self.test_user3 = self.app.central_userdb.get_user_by_eppn("hubba-fooo")
        # Temporarily fix email address locally until test user fixtures are merged
        self._fix_mail_addresses()
        self.scim_user1 = self._add_scim_user(
            scim_id=UUID("00000000-0000-0000-0000-000000000000"), eppn=self.test_user.eppn
        )
        self.scim_user2 = self._add_scim_user(
            scim_id=UUID("00000000-0000-0000-0000-000000000001"), eppn=self.test_user2.eppn
        )
        self.scim_group1 = self._add_scim_group(
            scim_id=UUID("00000000-0000-0000-0000-000000000002"), display_name="Test Group 1"
        )
        self.scim_group2 = self._add_scim_group(
            scim_id=UUID("00000000-0000-0000-0000-000000000003"), display_name="Test Group 2"
        )

    def _fix_mail_addresses(self) -> None:
        # Due to mixup in base user data
        correct_address = self.test_user2.mail_addresses.find("johnsmith2@example.com")
        assert correct_address is not None
        correct_address.is_verified = True
        self.test_user2.mail_addresses.set_primary(correct_address.key)
        self.test_user2.mail_addresses.remove(ElementKey("johnsmith@example.com"))
        self.app.central_userdb.save(self.test_user2)

    def load_app(self, config: Mapping[str, Any]) -> GroupManagementApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_group_management_app(test_config=config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                "eduid_site_url": "https://test.eduid.se/",
                "neo4j_config": {"encrypted": False},
                "neo4j_uri": self.neo4j_uri,
            }
        )
        return config

    def tearDown(self) -> None:
        super().tearDown()
        with self.app.app_context():
            self.neo4j_instance.purge_db()

    def _add_scim_user(self, scim_id: UUID, eppn: str) -> ScimApiUser:
        scim_user = ScimApiUser(scim_id=scim_id, external_id=f"{eppn}@eduid.se")
        self.app.scimapi_userdb.save(scim_user)
        scim_api_user = self.app.scimapi_userdb.get_user_by_scim_id(str(scim_user.scim_id))
        if not scim_api_user:
            raise RuntimeError("Failed to get created ScimApiUser")
        return scim_api_user

    def _add_scim_group(
        self, scim_id: UUID, display_name: str, extensions: GroupExtensions | None = None
    ) -> ScimApiGroup:
        if extensions is None:
            extensions = GroupExtensions()
        group = ScimApiGroup(scim_id=scim_id, display_name=display_name, extensions=extensions)
        self.app.scimapi_groupdb.save(group)
        group.graph = self.app.scimapi_groupdb.graphdb.save(group.graph)
        return group

    def _invite(
        self, group_scim_id: str, inviter: User, invite_address: str, role: str, expect_mail: bool = True
    ) -> TestResponse:
        # Clear messagedb before test
        self.app.messagedb._drop_whole_collection()
        with self.session_cookie(self.browser, inviter.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "group_identifier": group_scim_id,
                        "email_address": invite_address,
                        "role": role,
                        "csrf_token": sess.get_csrf_token(),
                    }
                response = client.post("/invites/create", data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_="POST_GROUP_INVITE_INVITES_CREATE_SUCCESS")
        # Verify that invite email was queued (unless self-invite)
        if expect_mail:
            assert self.app.messagedb.db_count() == 1
        else:
            assert self.app.messagedb.db_count() == 0
        return response

    def _accept_invite(self, group_scim_id: str, invitee: User, invite_address: str, role: str) -> TestResponse:
        with self.session_cookie(self.browser, invitee.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "group_identifier": group_scim_id,
                        "email_address": invite_address,
                        "role": role,
                        "csrf_token": sess.get_csrf_token(),
                    }
                response = client.post("/invites/accept", data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_="POST_GROUP_INVITE_INVITES_ACCEPT_SUCCESS")
        return response

    def _decline_invite(self, group_scim_id: str, invitee: User, invite_address: str, role: str) -> TestResponse:
        with self.session_cookie(self.browser, invitee.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "group_identifier": group_scim_id,
                        "email_address": invite_address,
                        "role": role,
                        "csrf_token": sess.get_csrf_token(),
                    }
                response = client.post("/invites/decline", data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_="POST_GROUP_INVITE_INVITES_DECLINE_SUCCESS")
        return response

    def _delete_invite(self, group_scim_id: str, inviter: User, invite_address: str, role: str) -> TestResponse:
        # Clear messagedb before test
        self.app.messagedb._drop_whole_collection()
        with self.session_cookie(self.browser, inviter.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "group_identifier": group_scim_id,
                        "email_address": invite_address,
                        "role": role,
                        "csrf_token": sess.get_csrf_token(),
                    }
                response = client.post("/invites/delete", data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_="POST_GROUP_INVITE_INVITES_DELETE_SUCCESS")
        # Verify that cancel email was queued
        assert self.app.messagedb.db_count() == 1
        return response

    def _invite_setup(self) -> None:
        # Add test user as group owner of two groups
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        self.scim_group2.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group2)

        # Invite test_user2 as owner and member of Test Group 1
        assert self.test_user2.mail_addresses.primary is not None
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="member",
        )
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="owner",
        )
        # Invite test_user3 as member of Test Group 1
        assert self.test_user3.mail_addresses.primary is not None
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user3.mail_addresses.primary.email,
            role="member",
        )
        # Invite test_user3 as member of Test Group 2
        self._invite(
            group_scim_id=str(self.scim_group2.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user3.mail_addresses.primary.email,
            role="member",
        )

    def test_app_starts(self) -> None:
        assert self.app.conf.app_name == "group_management"

    def test_get_groups(self) -> None:
        # Add test user as group member and owner
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.members = set([graph_user])
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        response = self.browser.get("/groups")
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get("/groups")
        self._check_success_response(response, type_="GET_GROUP_MANAGEMENT_GROUPS_SUCCESS")
        payload = self.get_response_payload(response)
        assert str(self.scim_user1.scim_id) == payload["user_identifier"]
        assert len(payload["groups"]) == 1
        assert payload["groups"][0]["display_name"] == "Test Group 1"
        assert payload["groups"][0]["is_owner"] is True
        assert payload["groups"][0]["is_member"] is True

    def test_get_member_groups_no_scim_user(self) -> None:
        # Remove test user from scim_userdb
        self.app.scimapi_userdb.remove(self.scim_user1)
        assert self.app.scimapi_userdb.get_user_by_scim_id(str(self.scim_user1.scim_id)) is None

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get("/groups")
        self._check_success_response(response, type_="GET_GROUP_MANAGEMENT_GROUPS_SUCCESS")
        payload = self.get_response_payload(response)
        assert payload["user_identifier"] is None
        assert len(payload["groups"]) == 0

    def test_create_group(self) -> None:
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"display_name": "Test Group 2", "csrf_token": sess.get_csrf_token()}
                response = client.post("/create", data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_="POST_GROUP_MANAGEMENT_CREATE_SUCCESS")
        payload = self.get_response_payload(response)
        assert len(payload["groups"]) == 1
        assert payload["groups"][0]["display_name"] == "Test Group 2"
        assert payload["groups"][0]["is_owner"] is True
        assert payload["groups"][0]["is_member"] is False
        assert self.app.scimapi_groupdb.group_exists(payload["groups"][0]["identifier"]) is True

    def test_create_group_no_scim_user(self) -> None:
        # Remove test user from scim_userdb
        self.app.scimapi_userdb.remove(self.scim_user1)
        assert self.app.scimapi_userdb.get_user_by_scim_id(str(self.scim_user1.scim_id)) is None

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"display_name": "Test Group 2", "csrf_token": sess.get_csrf_token()}
                response = client.post("/create", data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_="POST_GROUP_MANAGEMENT_CREATE_SUCCESS")
        payload = self.get_response_payload(response)
        assert len(payload["groups"]) == 1
        assert payload["groups"][0]["display_name"] == "Test Group 2"
        assert payload["groups"][0]["is_owner"] is True
        assert payload["groups"][0]["is_member"] is False
        assert self.app.scimapi_groupdb.group_exists(payload["groups"][0]["identifier"]) is True

    def test_delete_group(self) -> None:
        # Add test user as group owner of two groups
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)
        self.scim_group2.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group2)

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"group_identifier": str(self.scim_group1.scim_id), "csrf_token": sess.get_csrf_token()}
                response = client.post("/delete", data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_="POST_GROUP_MANAGEMENT_DELETE_SUCCESS")
        payload = self.get_response_payload(response)
        assert len(payload["groups"]) == 1

        assert self.app.scimapi_groupdb.group_exists(str(self.scim_group2.scim_id)) is True
        assert self.app.scimapi_groupdb.group_exists(str(self.scim_group1.scim_id)) is False

    def test_delete_group_no_scim_user(self) -> None:
        # Remove test user from scim_userdb
        self.app.scimapi_userdb.remove(self.scim_user1)
        assert self.app.scimapi_userdb.get_user_by_scim_id(str(self.scim_user1.scim_id)) is None

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"group_identifier": str(self.scim_group1.scim_id), "csrf_token": sess.get_csrf_token()}
                response = client.post("/delete", data=json.dumps(data), content_type=self.content_type_json)
        self._check_error_response(
            response, type_="POST_GROUP_MANAGEMENT_DELETE_FAIL", msg=GroupManagementMsg.user_does_not_exist
        )
        assert self.app.scimapi_groupdb.group_exists(str(self.scim_group1.scim_id)) is True

    def test_delete_group_not_owner(self) -> None:
        # Add test user as group member
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.members = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"group_identifier": str(self.scim_group1.scim_id), "csrf_token": sess.get_csrf_token()}
                response = client.post("/delete", data=json.dumps(data), content_type=self.content_type_json)
        self._check_error_response(
            response, type_="POST_GROUP_MANAGEMENT_DELETE_FAIL", msg=GroupManagementMsg.user_not_owner
        )
        assert self.app.scimapi_groupdb.group_exists(str(self.scim_group1.scim_id)) is True

    def test_delete_group_and_invites(self) -> None:
        # Add test user as group owner
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        self._invite_setup()
        assert len(self.app.invite_state_db.get_states_by_group_scim_id(str(self.scim_group1.scim_id))) == 3

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {"group_identifier": str(self.scim_group1.scim_id), "csrf_token": sess.get_csrf_token()}
                response = client.post("/delete", data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_="POST_GROUP_MANAGEMENT_DELETE_SUCCESS")

        assert self.app.scimapi_groupdb.group_exists(str(self.scim_group1.scim_id)) is False
        assert not self.app.invite_state_db.get_states_by_group_scim_id(str(self.scim_group1.scim_id))

    def test_remove_member(self) -> None:
        # Add test_user1 as group owner
        graph_user1 = GraphUser(identifier=str(self.scim_user1.scim_id), display_name="Test User 1")
        self.scim_group1.owners = set([graph_user1])
        # Add test_user2 as group member
        graph_user2 = GraphUser(identifier=str(self.scim_user2.scim_id), display_name="Test User 2")
        self.scim_group1.members = set([graph_user2])

        self.app.scimapi_groupdb.save(self.scim_group1)

        # Check that test_user2 is a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group is not None
        found_members = [member for member in group.graph.members if member.identifier == str(self.scim_user2.scim_id)]
        assert len(found_members) == 1

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "group_identifier": str(self.scim_group1.scim_id),
                        "user_identifier": str(self.scim_user2.scim_id),
                        "role": "member",
                        "csrf_token": sess.get_csrf_token(),
                    }
                response = client.post("/remove-user", data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_="POST_GROUP_MANAGEMENT_REMOVE_USER_SUCCESS")
        payload = self.get_response_payload(response)
        assert len(payload["groups"]) == 1

        # Check that test_user2 is no longer a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group is not None
        found_members = [member for member in group.graph.members if member.identifier == str(self.scim_user2.scim_id)]
        assert len(found_members) == 0

    def test_remove_member_not_owner(self) -> None:
        # Add test_user2 as group member
        graph_user2 = GraphUser(identifier=str(self.scim_user2.scim_id), display_name="Test User 2")
        self.scim_group1.members = set([graph_user2])

        self.app.scimapi_groupdb.save(self.scim_group1)

        # Check that test_user2 is a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group is not None
        found_members = [member for member in group.graph.members if member.identifier == str(self.scim_user2.scim_id)]
        assert len(found_members) == 1

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "group_identifier": str(self.scim_group1.scim_id),
                        "user_identifier": str(self.scim_user2.scim_id),
                        "role": "member",
                        "csrf_token": sess.get_csrf_token(),
                    }
                response = client.post("/remove-user", data=json.dumps(data), content_type=self.content_type_json)
        self._check_error_response(
            response, type_="POST_GROUP_MANAGEMENT_REMOVE_USER_FAIL", msg=GroupManagementMsg.user_not_owner
        )

        # Check that test_user2 is still a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group is not None
        found_members = [member for member in group.graph.members if member.identifier == str(self.scim_user2.scim_id)]
        assert len(found_members) == 1

    def test_remove_owner(self) -> None:
        # Add test_user1 and test_user2 as group owner
        graph_user1 = GraphUser(identifier=str(self.scim_user1.scim_id), display_name="Test User 1")
        graph_user2 = GraphUser(identifier=str(self.scim_user2.scim_id), display_name="Test User 2")
        self.scim_group1.owners = set([graph_user1, graph_user2])
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Check that test_user2 is an owner of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group is not None
        assert group.has_owner(self.scim_user2.scim_id) is True

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "group_identifier": str(self.scim_group1.scim_id),
                        "user_identifier": str(self.scim_user2.scim_id),
                        "role": "owner",
                        "csrf_token": sess.get_csrf_token(),
                    }
                response = client.post("/remove-user", data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_="POST_GROUP_MANAGEMENT_REMOVE_USER_SUCCESS")
        payload = self.get_response_payload(response)
        assert len(payload["groups"]) == 1
        assert payload["groups"][0]["is_owner"] is True
        assert payload["groups"][0]["is_member"] is False

        # Check that test_user2 is no longer a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group is not None
        assert group.has_owner(self.scim_user2.scim_id) is False

    def test_remove_last_owner(self) -> None:
        # Add test_user1 as group owner
        graph_user1 = GraphUser(identifier=str(self.scim_user1.scim_id), display_name="Test User 1")
        self.scim_group1.owners = set([graph_user1])
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Check that test_user1 is an owner of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group is not None
        found_owners = [owner for owner in group.graph.owners if owner.identifier == str(self.scim_user1.scim_id)]
        assert len(found_owners) == 1

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "group_identifier": str(self.scim_group1.scim_id),
                        "user_identifier": str(self.scim_user1.scim_id),
                        "role": "owner",
                        "csrf_token": sess.get_csrf_token(),
                    }
                response = client.post("/remove-user", data=json.dumps(data), content_type=self.content_type_json)
        self._check_error_response(response, type_="POST_GROUP_MANAGEMENT_REMOVE_USER_FAIL")

        # Check that test_user1 is still owner of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group is not None
        found_owners = [owner for owner in group.graph.owners if owner.identifier == str(self.scim_user1.scim_id)]
        assert len(found_owners) == 1

    def test_remove_self_member(self) -> None:
        # Add test_user1 as group member
        graph_user1 = GraphUser(identifier=str(self.scim_user1.scim_id), display_name="Test User 1")
        self.scim_group1.members = set([graph_user1])

        self.app.scimapi_groupdb.save(self.scim_group1)

        # Check that test_user1 is a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group is not None
        assert group.has_member(self.scim_user1.scim_id) is True

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "group_identifier": str(self.scim_group1.scim_id),
                        "user_identifier": str(self.scim_user1.scim_id),
                        "role": "member",
                        "csrf_token": sess.get_csrf_token(),
                    }
                response = client.post("/remove-user", data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_="POST_GROUP_MANAGEMENT_REMOVE_USER_SUCCESS")
        payload = self.get_response_payload(response)
        assert len(payload["groups"]) == 0

        # Check that test_user1 is no longer a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group is not None
        assert group.has_member(self.scim_user1.scim_id) is False

    def test_remove_non_existing_member(self) -> None:
        # Add test_user1 as group owner
        graph_user1 = GraphUser(identifier=str(self.scim_user1.scim_id), display_name="Test User 1")
        self.scim_group1.owners = set([graph_user1])

        self.app.scimapi_groupdb.save(self.scim_group1)

        # Check that test_user2 is not a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group is not None
        found_members = [member for member in group.graph.members if member.identifier == str(self.scim_user2.scim_id)]
        assert len(found_members) == 0

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        "group_identifier": str(self.scim_group1.scim_id),
                        "user_identifier": str(self.scim_user2.scim_id),
                        "role": "member",
                        "csrf_token": sess.get_csrf_token(),
                    }
                response = client.post("/remove-user", data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_="POST_GROUP_MANAGEMENT_REMOVE_USER_SUCCESS")
        payload = self.get_response_payload(response)
        assert len(payload["groups"]) == 1

        # Check that test_user2 is still not a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group is not None
        found_members = [member for member in group.graph.members if member.identifier == str(self.scim_user2.scim_id)]
        assert len(found_members) == 0

    def test_invite_member(self) -> None:
        # Add test user as group owner
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as member
        assert self.test_user2.mail_addresses.primary is not None
        response = self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="member",
        )
        payload = self.get_response_payload(response)
        outgoing = payload["outgoing"]
        assert len(outgoing) == 1
        for invite in outgoing:
            assert str(self.scim_group1.scim_id) == invite["group_identifier"]
            assert len(invite["member_invites"]) == 1
            assert len(invite["owner_invites"]) == 0

        assert (
            self.app.invite_state_db.get_state(
                group_scim_id=str(self.scim_group1.scim_id),
                email_address=self.test_user2.mail_addresses.primary.email,
                role=GroupRole.MEMBER,
            )
            is not None
        )

    def test_self_invite_member(self) -> None:
        # Add test user as group owner
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 1 to the group as member
        response = self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user.mail_addresses.primary.email,
            role="member",
            expect_mail=False,
        )
        payload = self.get_response_payload(response)
        outgoing = payload["outgoing"]
        assert len(outgoing) == 0

        assert not self.app.invite_state_db.get_state(
            group_scim_id=str(self.scim_group1.scim_id),
            email_address=self.test_user.mail_addresses.primary.email,
            role=GroupRole.MEMBER,
        )
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get("/groups")
        self._check_success_response(response, type_="GET_GROUP_MANAGEMENT_GROUPS_SUCCESS")
        payload = self.get_response_payload(response)
        assert str(self.scim_user1.scim_id) == payload["user_identifier"]
        assert len(payload["groups"]) == 1
        assert payload["groups"][0]["display_name"] == "Test Group 1"
        assert payload["groups"][0]["is_owner"] is True
        assert payload["groups"][0]["is_member"] is True

    def test_accept_invite_member(self) -> None:
        # Add test user as group owner
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as member
        assert self.test_user2.mail_addresses.primary is not None
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="member",
        )
        # Accept invite as test user 2
        response = self._accept_invite(
            group_scim_id=str(self.scim_group1.scim_id),
            invitee=self.test_user2,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="member",
        )
        payload = self.get_response_payload(response)
        incoming = payload["incoming"]
        assert len(incoming) == 0

        assert not self.app.invite_state_db.get_state(
            group_scim_id=str(self.scim_group1.scim_id),
            email_address=self.test_user2.mail_addresses.primary.email,
            role=GroupRole.MEMBER,
        )
        scim_group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert scim_group is not None
        scim_user = self.app.scimapi_userdb.get_user_by_external_id(
            f"{self.test_user2.eppn}@{self.app.conf.scim_external_id_scope}"
        )
        assert scim_user is not None
        assert scim_group.has_member(scim_user.scim_id) is True

    def test_decline_invite_member(self) -> None:
        # Add test user as group owner
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as member
        assert self.test_user2.mail_addresses.primary is not None
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="member",
        )
        # Decline invite as test user 2
        response = self._decline_invite(
            group_scim_id=str(self.scim_group1.scim_id),
            invitee=self.test_user2,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="member",
        )
        payload = self.get_response_payload(response)
        incoming = payload["incoming"]
        assert len(incoming) == 0

        assert not self.app.invite_state_db.get_state(
            group_scim_id=str(self.scim_group1.scim_id),
            email_address=self.test_user2.mail_addresses.primary.email,
            role=GroupRole.MEMBER,
        )
        scim_group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert scim_group is not None
        scim_user = self.app.scimapi_userdb.get_user_by_external_id(
            f"{self.test_user2.eppn}@{self.app.conf.scim_external_id_scope}"
        )
        assert scim_user is not None
        assert scim_group.has_member(scim_user.scim_id) is False

    def test_delete_invite_member(self) -> None:
        # Add test user as group owner
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as member
        assert self.test_user2.mail_addresses.primary is not None
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="member",
        )
        # Delete invite as test user
        response = self._delete_invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="member",
        )
        payload = self.get_response_payload(response)
        outgoing = payload["outgoing"]
        assert len(outgoing) == 0

        assert not self.app.invite_state_db.get_state(
            group_scim_id=str(self.scim_group1.scim_id),
            email_address=self.test_user2.mail_addresses.primary.email,
            role=GroupRole.MEMBER,
        )
        scim_group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert scim_group is not None
        scim_user = self.app.scimapi_userdb.get_user_by_external_id(
            f"{self.test_user2.eppn}@{self.app.conf.scim_external_id_scope}"
        )
        assert scim_user is not None
        assert scim_group.has_member(scim_user.scim_id) is False

    def test_invite_owner(self) -> None:
        # Add test user as group owner
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as owner
        assert self.test_user2.mail_addresses.primary is not None
        response = self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="owner",
        )
        payload = self.get_response_payload(response)
        outgoing = payload["outgoing"]
        assert len(outgoing) == 1
        for invite in outgoing:
            assert str(self.scim_group1.scim_id) == invite["group_identifier"]
            assert len(invite["member_invites"]) == 0
            assert len(invite["owner_invites"]) == 1
        assert (
            self.app.invite_state_db.get_state(
                group_scim_id=str(self.scim_group1.scim_id),
                email_address=self.test_user2.mail_addresses.primary.email,
                role=GroupRole.OWNER,
            )
            is not None
        )

    def test_self_invite_owner(self) -> None:
        # Add test user as group owner
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 1 to the group as owner
        response = self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user.mail_addresses.primary.email,
            role="owner",
            expect_mail=False,
        )
        payload = self.get_response_payload(response)
        outgoing = payload["outgoing"]
        assert len(outgoing) == 0

        assert not self.app.invite_state_db.get_state(
            group_scim_id=str(self.scim_group1.scim_id),
            email_address=self.test_user.mail_addresses.primary.email,
            role=GroupRole.OWNER,
        )
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get("/groups")
        self._check_success_response(response, type_="GET_GROUP_MANAGEMENT_GROUPS_SUCCESS")
        payload = self.get_response_payload(response)
        assert str(self.scim_user1.scim_id) == payload["user_identifier"]
        assert len(payload["groups"]) == 1
        assert payload["groups"][0]["display_name"] == "Test Group 1"
        assert payload["groups"][0]["is_owner"] is True
        assert payload["groups"][0]["is_member"] is False

    def test_accept_invite_owner(self) -> None:
        # Add test user as group owner
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as member
        assert self.test_user2.mail_addresses.primary is not None
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="owner",
        )
        # Accept invite as test user 2
        response = self._accept_invite(
            group_scim_id=str(self.scim_group1.scim_id),
            invitee=self.test_user2,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="owner",
        )
        payload = self.get_response_payload(response)
        incoming = payload["incoming"]
        assert len(incoming) == 0

        assert not self.app.invite_state_db.get_state(
            group_scim_id=str(self.scim_group1.scim_id),
            email_address=self.test_user2.mail_addresses.primary.email,
            role=GroupRole.OWNER,
        )
        scim_group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert scim_group is not None
        scim_user = self.app.scimapi_userdb.get_user_by_external_id(
            f"{self.test_user2.eppn}@{self.app.conf.scim_external_id_scope}"
        )
        assert scim_user is not None
        assert scim_group.has_owner(scim_user.scim_id) is True

    def test_decline_invite_owner(self) -> None:
        # Add test user as group owner
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as member
        assert self.test_user2.mail_addresses.primary is not None
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="owner",
        )
        # Decline invite as test user 2
        response = self._decline_invite(
            group_scim_id=str(self.scim_group1.scim_id),
            invitee=self.test_user2,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="owner",
        )
        payload = self.get_response_payload(response)
        incoming = payload["incoming"]
        assert len(incoming) == 0

        assert not self.app.invite_state_db.get_state(
            group_scim_id=str(self.scim_group1.scim_id),
            email_address=self.test_user2.mail_addresses.primary.email,
            role=GroupRole.OWNER,
        )
        scim_group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert scim_group is not None
        scim_user = self.app.scimapi_userdb.get_user_by_external_id(
            f"{self.test_user2.eppn}@{self.app.conf.scim_external_id_scope}"
        )
        assert scim_user is not None
        assert scim_group.has_owner(scim_user.scim_id) is False

    def test_delete_invite_owner(self) -> None:
        # Add test user as group owner
        assert self.test_user.mail_addresses.primary is not None
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = set([graph_user])
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as member
        assert self.test_user2.mail_addresses.primary is not None
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="owner",
        )

        # Decline invite as test user
        response = self._delete_invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="owner",
        )
        payload = self.get_response_payload(response)
        outgoing = payload["outgoing"]
        assert len(outgoing) == 0

        assert not self.app.invite_state_db.get_state(
            group_scim_id=str(self.scim_group1.scim_id),
            email_address=self.test_user2.mail_addresses.primary.email,
            role=GroupRole.OWNER,
        )
        scim_group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert scim_group is not None
        scim_user = self.app.scimapi_userdb.get_user_by_external_id(
            f"{self.test_user2.eppn}@{self.app.conf.scim_external_id_scope}"
        )
        assert scim_user is not None
        assert scim_group.has_owner(scim_user.scim_id) is False

    def test_all_invites(self) -> None:
        response = self.browser.get("/invites/all")
        assert response.status_code == HTTPStatus.UNAUTHORIZED

        self._invite_setup()

        # Check outgoing invites as test_user
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get("/invites/all", content_type=self.content_type_json)
        self._check_success_response(response, type_="GET_GROUP_INVITE_INVITES_ALL_SUCCESS")
        payload = self.get_response_payload(response)
        assert payload["incoming"] == []
        outgoing = payload["outgoing"]
        assert len(outgoing) == 2
        for invite in outgoing:
            if invite["group_identifier"] == str(self.scim_group1.scim_id):
                assert len(invite["member_invites"]) == 2
                assert len(invite["owner_invites"]) == 1
            elif invite["group_identifier"] == str(self.scim_group2.scim_id):
                assert len(invite["member_invites"]) == 1
                assert len(invite["owner_invites"]) == 0
            else:
                pytest.fail("Unknown group scim_id in outgoing invites")

        # Check incoming invites as test_user2
        with self.session_cookie(self.browser, self.test_user2.eppn) as client:
            response = client.get("/invites/all", content_type=self.content_type_json)
        self._check_success_response(response, type_="GET_GROUP_INVITE_INVITES_ALL_SUCCESS")
        payload = self.get_response_payload(response)
        assert payload["outgoing"] == []
        incoming = payload["incoming"]
        assert len(incoming) == 2
        assert self.test_user2.mail_addresses.primary is not None
        for invite in incoming:
            assert str(self.scim_group1.scim_id) == invite["group_identifier"]
            assert self.scim_group1.display_name == invite["display_name"]
            assert self.test_user2.mail_addresses.primary.email == invite["email_address"]
            assert len(invite["owners"]) == 1
            assert invite["role"] is not None

        # Check incoming invites as test_user3
        with self.session_cookie(self.browser, self.test_user3.eppn) as client:
            response = client.get("/invites/all", content_type=self.content_type_json)
        self._check_success_response(response, type_="GET_GROUP_INVITE_INVITES_ALL_SUCCESS")
        payload = self.get_response_payload(response)
        assert payload["outgoing"] == []
        incoming = payload["incoming"]
        assert len(incoming) == 2
        assert self.test_user3.mail_addresses.primary is not None
        for invite in incoming:
            assert invite["group_identifier"] is not None
            assert invite["display_name"] is not None
            assert self.test_user3.mail_addresses.primary.email == invite["email_address"]
            assert len(invite["owners"]) == 1
            assert GroupRole.MEMBER.value == invite["role"]

    def test_outgoing_invites(self) -> None:
        response = self.browser.get("/invites/outgoing")
        assert response.status_code == HTTPStatus.UNAUTHORIZED

        self._invite_setup()

        # Check outgoing invites as test_user
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get("/invites/outgoing", content_type=self.content_type_json)
        self._check_success_response(response, type_="GET_GROUP_INVITE_INVITES_OUTGOING_SUCCESS")
        payload = self.get_response_payload(response)
        assert payload.get("incoming") is None
        outgoing = payload["outgoing"]
        assert len(outgoing) == 2
        for invite in outgoing:
            if invite["group_identifier"] == str(self.scim_group1.scim_id):
                assert len(invite["member_invites"]) == 2
                assert len(invite["owner_invites"]) == 1
            elif invite["group_identifier"] == str(self.scim_group2.scim_id):
                assert len(invite["member_invites"]) == 1
                assert len(invite["owner_invites"]) == 0
            else:
                pytest.fail("Unknown group scim_id in outgoing invites")

    def test_incoming_invites(self) -> None:
        response = self.browser.get("/invites/incoming")
        assert response.status_code == HTTPStatus.UNAUTHORIZED

        self._invite_setup()

        # Check incoming invites as test_user2
        with self.session_cookie(self.browser, self.test_user2.eppn) as client:
            response = client.get("/invites/incoming", content_type=self.content_type_json)
        self._check_success_response(response, type_="GET_GROUP_INVITE_INVITES_INCOMING_SUCCESS")
        payload = self.get_response_payload(response)
        assert payload.get("outgoing") is None
        incoming = payload["incoming"]
        assert len(incoming) == 2
        assert self.test_user2.mail_addresses.primary is not None
        for invite in incoming:
            assert str(self.scim_group1.scim_id) == invite["group_identifier"]
            assert self.scim_group1.display_name == invite["display_name"]
            assert self.test_user2.mail_addresses.primary.email == invite["email_address"]
            assert len(invite["owners"]) == 1
            assert invite["role"] is not None

        # Check incoming invites as test_user3
        with self.session_cookie(self.browser, self.test_user3.eppn) as client:
            response = client.get("/invites/incoming", content_type=self.content_type_json)
        self._check_success_response(response, type_="GET_GROUP_INVITE_INVITES_INCOMING_SUCCESS")
        payload = self.get_response_payload(response)
        assert payload.get("outgoing") is None
        incoming = payload["incoming"]
        assert len(incoming) == 2
        assert self.test_user3.mail_addresses.primary is not None
        for invite in incoming:
            assert invite["group_identifier"] is not None
            assert invite["display_name"] is not None
            assert self.test_user3.mail_addresses.primary.email == invite["email_address"]
            assert len(invite["owners"]) == 1
            assert GroupRole.MEMBER.value == invite["role"]

    def test_get_all_data(self) -> None:
        response = self.browser.get("/all-data")
        assert response.status_code == HTTPStatus.UNAUTHORIZED

        self._invite_setup()

        # Test with owner and invited
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get("/all-data", content_type=self.content_type_json)
        self._check_success_response(response, type_="GET_GROUP_MANAGEMENT_ALL_DATA_SUCCESS")
        payload = self.get_response_payload(response)
        assert str(self.scim_user1.scim_id) == payload["user_identifier"]
        assert len(payload["outgoing"]) == 2
        assert len(payload["groups"]) == 2

        # Accept member invite as test user 2
        assert self.test_user2.mail_addresses.primary is not None
        self._accept_invite(
            group_scim_id=str(self.scim_group1.scim_id),
            invitee=self.test_user2,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="member",
        )

        # Test with member and invitee
        with self.session_cookie(self.browser, self.test_user2.eppn) as client:
            response = client.get("/all-data", content_type=self.content_type_json)
        self._check_success_response(response, type_="GET_GROUP_MANAGEMENT_ALL_DATA_SUCCESS")
        payload = self.get_response_payload(response)
        assert str(self.scim_user2.scim_id) == payload["user_identifier"]
        assert len(payload["incoming"]) == 1
        assert len(payload["groups"]) == 1

        # Test with only invites
        with self.session_cookie(self.browser, self.test_user3.eppn) as client:
            response = client.get("/all-data", content_type=self.content_type_json)
        self._check_success_response(response, type_="GET_GROUP_MANAGEMENT_ALL_DATA_SUCCESS")
        payload = self.get_response_payload(response)
        assert payload["user_identifier"] is None
        assert len(payload["incoming"]) == 2
        assert len(payload["groups"]) == 0

    def test_get_all_data_privacy(self) -> None:
        # Add test user as group member and owner, add test user 2 as member
        assert self.test_user.mail_addresses.primary is not None
        graph_user1 = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        assert self.test_user2.mail_addresses.primary is not None
        graph_user2 = GraphUser(
            identifier=str(self.scim_user2.scim_id), display_name=self.test_user2.mail_addresses.primary.email
        )
        self.scim_group1.members = set([graph_user1, graph_user2])
        self.scim_group1.owners = set([graph_user1])
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 as owner
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role="owner",
        )

        # Get all data as test user 1
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get("/all-data")
        self._check_success_response(response, type_="GET_GROUP_MANAGEMENT_ALL_DATA_SUCCESS")
        payload = self.get_response_payload(response)
        # As owner the user see both members and owners
        assert normalised_data(
            [
                {
                    "display_name": "Test Group 1",
                    "identifier": "00000000-0000-0000-0000-000000000002",
                    "is_member": True,
                    "is_owner": True,
                    "members": [
                        {"display_name": "johnsmith@example.com", "identifier": "00000000-0000-0000-0000-000000000000"},
                        {
                            "display_name": "johnsmith2@example.com",
                            "identifier": "00000000-0000-0000-0000-000000000001",
                        },
                    ],
                    "owners": [
                        {"display_name": "johnsmith@example.com", "identifier": "00000000-0000-0000-0000-000000000000"}
                    ],
                }
            ]
        ) == normalised_data(payload["groups"])
        # As owner the user see your outgoing invites
        assert normalised_data(
            [
                {
                    "group_identifier": "00000000-0000-0000-0000-000000000002",
                    "member_invites": [],
                    "owner_invites": [{"email_address": "johnsmith2@example.com"}],
                }
            ]
        ) == normalised_data(payload["outgoing"])
        # test user 1 does not have any incoming invites
        assert normalised_data(payload["incoming"]) == []

        # Get all data as test user 2
        with self.session_cookie(self.browser, self.test_user2.eppn) as client:
            response = client.get("/all-data")
        self._check_success_response(response, type_="GET_GROUP_MANAGEMENT_ALL_DATA_SUCCESS")
        payload = self.get_response_payload(response)
        # As member the user only see owners and themselves as member for a group
        assert normalised_data(
            [
                {
                    "display_name": "Test Group 1",
                    "identifier": "00000000-0000-0000-0000-000000000002",
                    "is_member": True,
                    "is_owner": False,
                    "members": [
                        {"display_name": "johnsmith2@example.com", "identifier": "00000000-0000-0000-0000-000000000001"}
                    ],
                    "owners": [
                        {"display_name": "johnsmith@example.com", "identifier": "00000000-0000-0000-0000-000000000000"}
                    ],
                }
            ]
        ) == normalised_data(payload["groups"])
        # test user 2 does not have any outgoing invites
        assert payload["outgoing"] == []
        # as an invitee the user see incoming invites
        assert normalised_data(
            [
                {
                    "display_name": "Test Group 1",
                    "email_address": "johnsmith2@example.com",
                    "group_identifier": "00000000-0000-0000-0000-000000000002",
                    "owners": [
                        {"display_name": "johnsmith@example.com", "identifier": "00000000-0000-0000-0000-000000000000"}
                    ],
                    "role": "owner",
                }
            ]
        ) == normalised_data(payload["incoming"])
