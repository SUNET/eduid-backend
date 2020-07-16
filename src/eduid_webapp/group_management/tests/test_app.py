# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the SUNET nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
import json
from typing import Any, Optional
from uuid import UUID

from flask import Response
from mock import patch

from eduid_common.api.testing import EduidAPITestCase, normalised_data
from eduid_graphdb.groupdb import User as GraphUser
from eduid_graphdb.testing import Neo4jTemporaryInstance
from eduid_scimapi.groupdb import GroupExtensions, ScimApiGroup
from eduid_scimapi.userdb import ScimApiUser
from eduid_userdb import User
from eduid_userdb.exceptions import DocumentDoesNotExist

from eduid_webapp.group_management.app import init_group_management_app
from eduid_webapp.group_management.helpers import GroupManagementMsg
from eduid_webapp.group_management.schemas import GroupRole
from eduid_webapp.group_management.settings.common import GroupManagementConfig

__author__ = 'lundberg'


class GroupManagementTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    neo4j_instance: Neo4jTemporaryInstance
    neo4j_uri: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.neo4j_instance = Neo4jTemporaryInstance.get_instance()
        cls.neo4j_uri = (
            f'bolt://{cls.neo4j_instance.DEFAULT_USERNAME}:{cls.neo4j_instance.DEFAULT_PASSWORD}'
            f'@localhost:{cls.neo4j_instance.bolt_port}'
        )
        super().setUpClass()

    def setUp(self, **kwargs):
        users = ['hubba-bubba', 'hubba-baar', 'hubba-fooo']
        super(GroupManagementTests, self).setUp(users=users, **kwargs)
        self.test_user2 = self.app.central_userdb.get_user_by_eppn('hubba-baar')
        self.test_user3 = self.app.central_userdb.get_user_by_eppn('hubba-fooo')
        # Temporarily fix email address locally until test user fixtures are merged
        self._fix_mail_addresses()
        self.scim_user1 = self._add_scim_user(
            scim_id=UUID('00000000-0000-0000-0000-000000000000'), eppn=self.test_user.eppn
        )
        self.scim_user2 = self._add_scim_user(
            scim_id=UUID('00000000-0000-0000-0000-000000000001'), eppn=self.test_user2.eppn
        )
        self.scim_group1 = self._add_scim_group(
            scim_id=UUID('00000000-0000-0000-0000-000000000002'), display_name='Test Group 1'
        )
        self.scim_group2 = self._add_scim_group(
            scim_id=UUID('00000000-0000-0000-0000-000000000003'), display_name='Test Group 2'
        )

    def _fix_mail_addresses(self):
        # Due to mixup in base user data
        correct_address = self.test_user2.mail_addresses.find('johnsmith2@example.com')
        correct_address.is_verified = True
        self.test_user2.mail_addresses.primary = correct_address.email
        self.test_user2.mail_addresses.remove('johnsmith@example.com')
        self.app.central_userdb.save(self.test_user2)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_group_management_app('testing', config)

    def update_config(self, config):
        config.update({'neo4j_uri': self.neo4j_uri, 'neo4j_config': {'encrypted': False}})
        return GroupManagementConfig(**config)

    def tearDown(self):
        super(GroupManagementTests, self).tearDown()
        with self.app.app_context():
            self.neo4j_instance.purge_db()
            self.app.central_userdb._drop_whole_collection()
            self.app.scimapi_userdb._drop_whole_collection()
            self.app.scimapi_groupdb._drop_whole_collection()
            self.app.invite_state_db._drop_whole_collection()

    def _add_scim_user(self, scim_id: UUID, eppn: str) -> ScimApiUser:
        scim_user = ScimApiUser(scim_id=scim_id, external_id=f'{eppn}@eduid.se')
        self.app.scimapi_userdb.save(scim_user)
        return self.app.scimapi_userdb.get_user_by_scim_id(str(scim_user.scim_id))

    def _add_scim_group(
        self, scim_id: UUID, display_name: str, extensions: Optional[GroupExtensions] = None
    ) -> ScimApiGroup:
        if extensions is None:
            extensions = GroupExtensions()
        group = ScimApiGroup(scim_id=scim_id, display_name=display_name, extensions=extensions)
        self.app.scimapi_groupdb.save(group)
        group.graph = self.app.scimapi_groupdb.graphdb.save(group.graph)
        return group

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def _invite(
        self, mock_sendmail: Any, group_scim_id: str, inviter: User, invite_address: str, role: str
    ) -> Response:
        mock_sendmail.return_value = True
        with self.session_cookie(self.browser, inviter.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'group_identifier': group_scim_id,
                        'email_address': invite_address,
                        'role': role,
                        'csrf_token': sess.get_csrf_token(),
                    }
                    response = client.post(
                        '/invites/create', data=json.dumps(data), content_type=self.content_type_json
                    )
        self._check_success_response(response, type_='POST_GROUP_INVITE_INVITES_CREATE_SUCCESS')
        return response

    def _accept_invite(self, group_scim_id: str, invitee: User, invite_address: str, role: str) -> Response:
        with self.session_cookie(self.browser, invitee.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'group_identifier': group_scim_id,
                        'email_address': invite_address,
                        'role': role,
                        'csrf_token': sess.get_csrf_token(),
                    }
                    response = client.post(
                        '/invites/accept', data=json.dumps(data), content_type=self.content_type_json
                    )
        self._check_success_response(response, type_='POST_GROUP_INVITE_INVITES_ACCEPT_SUCCESS')
        return response

    def _decline_invite(self, group_scim_id: str, invitee: User, invite_address: str, role: str) -> Response:
        with self.session_cookie(self.browser, invitee.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'group_identifier': group_scim_id,
                        'email_address': invite_address,
                        'role': role,
                        'csrf_token': sess.get_csrf_token(),
                    }
                    response = client.post(
                        '/invites/decline', data=json.dumps(data), content_type=self.content_type_json
                    )
        self._check_success_response(response, type_='POST_GROUP_INVITE_INVITES_DECLINE_SUCCESS')
        return response

    def _invite_setup(self):
        # Add test user as group owner of two groups
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = [graph_user]
        self.app.scimapi_groupdb.save(self.scim_group1)

        self.scim_group2.owners = [graph_user]
        self.app.scimapi_groupdb.save(self.scim_group2)

        # Invite test_user2 as owner and member of Test Group 1
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='member',
        )
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='owner',
        )
        # Invite test_user3 as member of Test Group 1
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user3.mail_addresses.primary.email,
            role='member',
        )
        # Invite test_user3 as member of Test Group 2
        self._invite(
            group_scim_id=str(self.scim_group2.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user3.mail_addresses.primary.email,
            role='member',
        )

    def test_app_starts(self):
        assert self.app.config.app_name == "group_management"

    def test_get_groups(self):
        # Add test user as group member and owner
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.members = [graph_user]
        self.scim_group1.owners = [graph_user]
        self.app.scimapi_groupdb.save(self.scim_group1)

        response = self.browser.get('/groups')
        assert response.status_code == 302  # Redirect to token service
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get('/groups')
        self._check_success_response(response, type_='GET_GROUP_MANAGEMENT_GROUPS_SUCCESS')
        payload = response.json.get('payload')
        assert 1 == len(payload['member_of'])
        assert 1 == len(payload['owner_of'])
        assert 'Test Group 1' == payload['member_of'][0]['display_name']
        assert 'Test Group 1' == payload['owner_of'][0]['display_name']

    def test_get_member_groups_no_scim_user(self):
        # Remove test user from scim_userdb
        self.app.scimapi_userdb.remove(self.scim_user1)
        assert self.app.scimapi_userdb.get_user_by_scim_id(self.scim_user1.scim_id) is None

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get('/groups')
        self._check_success_response(response, type_='GET_GROUP_MANAGEMENT_GROUPS_SUCCESS')
        payload = response.json.get('payload')
        assert 0 == len(payload['member_of'])
        assert 0 == len(payload['owner_of'])

    def test_create_group(self):
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {'display_name': 'Test Group 2', 'csrf_token': sess.get_csrf_token()}
                    response = client.post('/create', data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_='POST_GROUP_MANAGEMENT_CREATE_SUCCESS')
        payload = response.json.get('payload')
        assert 1 == len(payload['member_of'])
        assert 1 == len(payload['owner_of'])
        assert 'Test Group 2' == payload['member_of'][0]['display_name']
        assert 'Test Group 2' == payload['owner_of'][0]['display_name']
        assert self.app.scimapi_groupdb.group_exists(payload['owner_of'][0]['identifier']) is True

    def test_create_group_no_scim_user(self):
        # Remove test user from scim_userdb
        self.app.scimapi_userdb.remove(self.scim_user1)
        assert self.app.scimapi_userdb.get_user_by_scim_id(self.scim_user1.scim_id) is None

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {'display_name': 'Test Group 2', 'csrf_token': sess.get_csrf_token()}
                    response = client.post('/create', data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_='POST_GROUP_MANAGEMENT_CREATE_SUCCESS')
        payload = response.json.get('payload')
        assert 1 == len(payload['member_of'])
        assert 1 == len(payload['owner_of'])
        assert 'Test Group 2' == payload['member_of'][0]['display_name']
        assert 'Test Group 2' == payload['owner_of'][0]['display_name']
        assert self.app.scimapi_groupdb.group_exists(payload['owner_of'][0]['identifier']) is True

    def test_delete_group(self):
        # Add test user as group owner of two groups
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = [graph_user]
        self.app.scimapi_groupdb.save(self.scim_group1)
        self.scim_group2.owners = [graph_user]
        self.app.scimapi_groupdb.save(self.scim_group2)

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {'group_identifier': str(self.scim_group1.scim_id), 'csrf_token': sess.get_csrf_token()}
                    response = client.post('/delete', data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_='POST_GROUP_MANAGEMENT_DELETE_SUCCESS')
        payload = response.json.get('payload')
        assert 0 == len(payload['member_of'])
        assert 1 == len(payload['owner_of'])

        assert self.app.scimapi_groupdb.group_exists(str(self.scim_group2.scim_id)) is True
        assert self.app.scimapi_groupdb.group_exists(str(self.scim_group1.scim_id)) is False

    def test_delete_group_no_scim_user(self):
        # Remove test user from scim_userdb
        self.app.scimapi_userdb.remove(self.scim_user1)
        assert self.app.scimapi_userdb.get_user_by_scim_id(self.scim_user1.scim_id) is None

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {'group_identifier': str(self.scim_group1.scim_id), 'csrf_token': sess.get_csrf_token()}
                    response = client.post('/delete', data=json.dumps(data), content_type=self.content_type_json)
        self._check_error_response(
            response, type_='POST_GROUP_MANAGEMENT_DELETE_FAIL', msg=GroupManagementMsg.user_does_not_exist
        )
        assert self.app.scimapi_groupdb.group_exists(str(self.scim_group1.scim_id)) is True

    def test_delete_group_not_owner(self):
        # Add test user as group member
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.members = [graph_user]
        self.app.scimapi_groupdb.save(self.scim_group1)

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {'group_identifier': str(self.scim_group1.scim_id), 'csrf_token': sess.get_csrf_token()}
                    response = client.post('/delete', data=json.dumps(data), content_type=self.content_type_json)
        self._check_error_response(
            response, type_='POST_GROUP_MANAGEMENT_DELETE_FAIL', msg=GroupManagementMsg.user_not_owner
        )
        assert self.app.scimapi_groupdb.group_exists(str(self.scim_group1.scim_id)) is True

    def test_delete_group_and_invites(self):
        # Add test user as group owner
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = [graph_user]
        self.app.scimapi_groupdb.save(self.scim_group1)

        self._invite_setup()
        assert 3 == len(self.app.invite_state_db.get_states_by_group_scim_id(str(self.scim_group1.scim_id)))

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {'group_identifier': str(self.scim_group1.scim_id), 'csrf_token': sess.get_csrf_token()}
                    response = client.post('/delete', data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_='POST_GROUP_MANAGEMENT_DELETE_SUCCESS')

        assert self.app.scimapi_groupdb.group_exists(str(self.scim_group1.scim_id)) is False
        with self.assertRaises(DocumentDoesNotExist):
            self.app.invite_state_db.get_states_by_group_scim_id(str(self.scim_group1.scim_id))

    def test_remove_member(self):
        # Add test_user1 as group owner
        graph_user1 = GraphUser(identifier=str(self.scim_user1.scim_id), display_name='Test User 1')
        self.scim_group1.owners = [graph_user1]
        # Add test_user2 as group member
        graph_user2 = GraphUser(identifier=str(self.scim_user2.scim_id), display_name='Test User 2')
        self.scim_group1.members = [graph_user2]

        self.app.scimapi_groupdb.save(self.scim_group1)

        # Check that test_user2 is a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        found_members = [member for member in group.graph.members if member.identifier == str(self.scim_user2.scim_id)]
        assert 1 == len(found_members)

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'group_identifier': str(self.scim_group1.scim_id),
                        'user_identifier': str(self.scim_user2.scim_id),
                        'role': 'member',
                        'csrf_token': sess.get_csrf_token(),
                    }
                    response = client.post('/remove-user', data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_='POST_GROUP_MANAGEMENT_REMOVE_USER_SUCCESS')
        payload = response.json.get('payload')
        assert 0 == len(payload['member_of'])
        assert 1 == len(payload['owner_of'])

        # Check that test_user2 is no longer a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        found_members = [member for member in group.graph.members if member.identifier == str(self.scim_user2.scim_id)]
        assert 0 == len(found_members)

    def test_remove_member_not_owner(self):
        # Add test_user2 as group member
        graph_user2 = GraphUser(identifier=str(self.scim_user2.scim_id), display_name='Test User 2')
        self.scim_group1.members = [graph_user2]

        self.app.scimapi_groupdb.save(self.scim_group1)

        # Check that test_user2 is a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        found_members = [member for member in group.graph.members if member.identifier == str(self.scim_user2.scim_id)]
        assert 1 == len(found_members)

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'group_identifier': str(self.scim_group1.scim_id),
                        'user_identifier': str(self.scim_user2.scim_id),
                        'role': 'member',
                        'csrf_token': sess.get_csrf_token(),
                    }
                    response = client.post('/remove-user', data=json.dumps(data), content_type=self.content_type_json)
        self._check_error_response(
            response, type_='POST_GROUP_MANAGEMENT_REMOVE_USER_FAIL', msg=GroupManagementMsg.user_not_owner
        )

        # Check that test_user2 is still a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        found_members = [member for member in group.graph.members if member.identifier == str(self.scim_user2.scim_id)]
        assert 1 == len(found_members)

    def test_remove_owner(self):
        # Add test_user1 and test_user2 as group owner
        graph_user1 = GraphUser(identifier=str(self.scim_user1.scim_id), display_name='Test User 1')
        graph_user2 = GraphUser(identifier=str(self.scim_user2.scim_id), display_name='Test User 2')
        self.scim_group1.owners = [graph_user1, graph_user2]
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Check that test_user2 is an owner of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group.has_owner(self.scim_user2.scim_id) is True

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'group_identifier': str(self.scim_group1.scim_id),
                        'user_identifier': str(self.scim_user2.scim_id),
                        'role': 'owner',
                        'csrf_token': sess.get_csrf_token(),
                    }
                    response = client.post('/remove-user', data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_='POST_GROUP_MANAGEMENT_REMOVE_USER_SUCCESS')
        payload = response.json.get('payload')
        assert 0 == len(payload['member_of'])
        assert 1 == len(payload['owner_of'])

        # Check that test_user2 is no longer a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group.has_owner(self.scim_user2.scim_id) is False

    def test_remove_last_owner(self):
        # Add test_user1 as group owner
        graph_user1 = GraphUser(identifier=str(self.scim_user1.scim_id), display_name='Test User 1')
        self.scim_group1.owners = [graph_user1]
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Check that test_user1 is an owner of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        found_owners = [owner for owner in group.graph.owners if owner.identifier == str(self.scim_user1.scim_id)]
        assert 1 == len(found_owners)

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'group_identifier': str(self.scim_group1.scim_id),
                        'user_identifier': str(self.scim_user1.scim_id),
                        'role': 'owner',
                        'csrf_token': sess.get_csrf_token(),
                    }
                    response = client.post('/remove-user', data=json.dumps(data), content_type=self.content_type_json)
        self._check_error_response(response, type_='POST_GROUP_MANAGEMENT_REMOVE_USER_FAIL')

        # Check that test_user1 is still owner of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        found_owners = [owner for owner in group.graph.owners if owner.identifier == str(self.scim_user1.scim_id)]
        assert 1 == len(found_owners)

    def test_remove_self_member(self):
        # Add test_user1 as group member
        graph_user1 = GraphUser(identifier=str(self.scim_user1.scim_id), display_name='Test User 1')
        self.scim_group1.members = [graph_user1]

        self.app.scimapi_groupdb.save(self.scim_group1)

        # Check that test_user1 is a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group.has_member(self.scim_user1.scim_id) is True

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'group_identifier': str(self.scim_group1.scim_id),
                        'user_identifier': str(self.scim_user1.scim_id),
                        'role': 'member',
                        'csrf_token': sess.get_csrf_token(),
                    }
                    response = client.post('/remove-user', data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_='POST_GROUP_MANAGEMENT_REMOVE_USER_SUCCESS')
        payload = response.json.get('payload')
        assert 0 == len(payload['member_of'])
        assert 0 == len(payload['owner_of'])

        # Check that test_user1 is no longer a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        assert group.has_member(self.scim_user1.scim_id) is False

    def test_remove_non_existing_member(self):
        # Add test_user1 as group owner
        graph_user1 = GraphUser(identifier=str(self.scim_user1.scim_id), display_name='Test User 1')
        self.scim_group1.owners = [graph_user1]

        self.app.scimapi_groupdb.save(self.scim_group1)

        # Check that test_user2 is not a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        found_members = [member for member in group.graph.members if member.identifier == str(self.scim_user2.scim_id)]
        assert 0 == len(found_members)

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'group_identifier': str(self.scim_group1.scim_id),
                        'user_identifier': str(self.scim_user2.scim_id),
                        'role': 'member',
                        'csrf_token': sess.get_csrf_token(),
                    }
                    response = client.post('/remove-user', data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(response, type_='POST_GROUP_MANAGEMENT_REMOVE_USER_SUCCESS')
        payload = response.json.get('payload')
        assert 0 == len(payload['member_of'])
        assert 1 == len(payload['owner_of'])

        # Check that test_user2 is still not a member of scim_group1
        group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        found_members = [member for member in group.graph.members if member.identifier == str(self.scim_user2.scim_id)]
        assert 0 == len(found_members)

    def test_invite_member(self):
        # Add test user as group owner
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = [graph_user]
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as member
        response = self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='member',
        )
        payload = response.json.get('payload')
        outgoing = payload['outgoing']
        assert 1 == len(outgoing)
        for invite in outgoing:
            assert str(self.scim_group1.scim_id) == invite['group_identifier']
            assert 1 == len(invite['member_invites'])
            assert 0 == len(invite['owner_invites'])

        assert (
            self.app.invite_state_db.get_state(
                group_scim_id=str(self.scim_group1.scim_id),
                email_address=self.test_user2.mail_addresses.primary.email,
                role=GroupRole.MEMBER,
            )
            is not None
        )

    def test_accept_invite_member(self):
        # Add test user as group owner
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = [graph_user]
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as member
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='member',
        )
        # Accept invite as test user 2
        response = self._accept_invite(
            group_scim_id=str(self.scim_group1.scim_id),
            invitee=self.test_user2,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='member',
        )
        payload = response.json.get('payload')
        incoming = payload['incoming']
        assert 0 == len(incoming)

        with self.assertRaises(DocumentDoesNotExist):
            self.app.invite_state_db.get_state(
                group_scim_id=str(self.scim_group1.scim_id),
                email_address=self.test_user2.mail_addresses.primary.email,
                role=GroupRole.MEMBER,
            )
        scim_group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        scim_user = self.app.scimapi_userdb.get_user_by_external_id(
            f'{self.test_user2.eppn}@{self.app.config.scim_external_id_scope}'
        )
        assert scim_group.has_member(scim_user.scim_id) is True

    def test_decline_invite_member(self):
        # Add test user as group owner
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = [graph_user]
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as member
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='member',
        )
        # Decline invite as test user 2
        response = self._decline_invite(
            group_scim_id=str(self.scim_group1.scim_id),
            invitee=self.test_user2,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='member',
        )
        payload = response.json.get('payload')
        incoming = payload['incoming']
        assert 0 == len(incoming)

        with self.assertRaises(DocumentDoesNotExist):
            self.app.invite_state_db.get_state(
                group_scim_id=str(self.scim_group1.scim_id),
                email_address=self.test_user2.mail_addresses.primary.email,
                role=GroupRole.MEMBER,
            )
        scim_group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        scim_user = self.app.scimapi_userdb.get_user_by_external_id(
            f'{self.test_user2.eppn}@{self.app.config.scim_external_id_scope}'
        )
        assert scim_group.has_member(scim_user.scim_id) is False

    def test_invite_owner(self):
        # Add test user as group owner
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = [graph_user]
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as owner
        response = self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='owner',
        )
        payload = response.json.get('payload')
        outgoing = payload['outgoing']
        assert 1 == len(outgoing)
        for invite in outgoing:
            assert str(self.scim_group1.scim_id) == invite['group_identifier']
            assert 0 == len(invite['member_invites'])
            assert 1 == len(invite['owner_invites'])
        assert (
            self.app.invite_state_db.get_state(
                group_scim_id=str(self.scim_group1.scim_id),
                email_address=self.test_user2.mail_addresses.primary.email,
                role=GroupRole.OWNER,
            )
            is not None
        )

    def test_accept_invite_owner(self):
        # Add test user as group owner
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = [graph_user]
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as member
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='owner',
        )
        # Accept invite as test user 2
        response = self._accept_invite(
            group_scim_id=str(self.scim_group1.scim_id),
            invitee=self.test_user2,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='owner',
        )
        payload = response.json.get('payload')
        incoming = payload['incoming']
        assert 0 == len(incoming)

        with self.assertRaises(DocumentDoesNotExist):
            self.app.invite_state_db.get_state(
                group_scim_id=str(self.scim_group1.scim_id),
                email_address=self.test_user2.mail_addresses.primary.email,
                role=GroupRole.MEMBER,
            )
        scim_group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        scim_user = self.app.scimapi_userdb.get_user_by_external_id(
            f'{self.test_user2.eppn}@{self.app.config.scim_external_id_scope}'
        )
        assert scim_group.has_owner(scim_user.scim_id) is True

    def test_decline_invite_owner(self):
        # Add test user as group owner
        graph_user = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        self.scim_group1.owners = [graph_user]
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 to the group as member
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='owner',
        )
        # Decline invite as test user 2
        response = self._decline_invite(
            group_scim_id=str(self.scim_group1.scim_id),
            invitee=self.test_user2,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='owner',
        )
        payload = response.json.get('payload')
        incoming = payload['incoming']
        assert 0 == len(incoming)

        with self.assertRaises(DocumentDoesNotExist):
            self.app.invite_state_db.get_state(
                group_scim_id=str(self.scim_group1.scim_id),
                email_address=self.test_user2.mail_addresses.primary.email,
                role=GroupRole.MEMBER,
            )
        scim_group = self.app.scimapi_groupdb.get_group_by_scim_id(str(self.scim_group1.scim_id))
        scim_user = self.app.scimapi_userdb.get_user_by_external_id(
            f'{self.test_user2.eppn}@{self.app.config.scim_external_id_scope}'
        )
        assert scim_group.has_owner(scim_user.scim_id) is False

    def test_all_invites(self):
        response = self.browser.get('/invites/all')
        assert 302 == response.status_code  # Redirect to token service

        self._invite_setup()

        # Check outgoing invites as test_user
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get('/invites/all', content_type=self.content_type_json)
        self._check_success_response(response, type_='GET_GROUP_INVITE_INVITES_ALL_SUCCESS')
        payload = response.json.get('payload')
        assert [] == payload['incoming']
        outgoing = payload['outgoing']
        assert 2 == len(outgoing)
        for invite in outgoing:
            if invite['group_identifier'] == str(self.scim_group1.scim_id):
                assert 2 == len(invite['member_invites'])
                assert 1 == len(invite['owner_invites'])
            elif invite['group_identifier'] == str(self.scim_group2.scim_id):
                assert 1 == len(invite['member_invites'])
                assert 0 == len(invite['owner_invites'])
            else:
                assert False, 'Unknown group scim_id in outgoing invites'

        # Check incoming invites as test_user2
        with self.session_cookie(self.browser, self.test_user2.eppn) as client:
            response = client.get('/invites/all', content_type=self.content_type_json)
        self._check_success_response(response, type_='GET_GROUP_INVITE_INVITES_ALL_SUCCESS')
        payload = response.json.get('payload')
        assert [] == payload['outgoing']
        incoming = payload['incoming']
        assert 2 == len(incoming)
        for invite in incoming:
            assert str(self.scim_group1.scim_id) == invite['group_identifier']
            assert self.scim_group1.display_name == invite['display_name']
            assert self.test_user2.mail_addresses.primary.email == invite['email_address']
            assert 1 == len(invite['owners'])
            assert invite['role'] is not None

        # Check incoming invites as test_user3
        with self.session_cookie(self.browser, self.test_user3.eppn) as client:
            response = client.get('/invites/all', content_type=self.content_type_json)
        self._check_success_response(response, type_='GET_GROUP_INVITE_INVITES_ALL_SUCCESS')
        payload = response.json.get('payload')
        assert [] == payload['outgoing']
        incoming = payload['incoming']
        assert 2 == len(incoming)
        for invite in incoming:
            assert invite['group_identifier'] is not None
            assert invite['display_name'] is not None
            assert self.test_user3.mail_addresses.primary.email == invite['email_address']
            assert 1 == len(invite['owners'])
            assert GroupRole.MEMBER.value == invite['role']

    def test_outgoing_invites(self):
        response = self.browser.get('/invites/outgoing')
        assert 302 == response.status_code  # Redirect to token service

        self._invite_setup()

        # Check outgoing invites as test_user
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get('/invites/outgoing', content_type=self.content_type_json)
        self._check_success_response(response, type_='GET_GROUP_INVITE_INVITES_OUTGOING_SUCCESS')
        payload = response.json.get('payload')
        assert payload.get('incoming') is None
        outgoing = payload['outgoing']
        assert 2 == len(outgoing)
        for invite in outgoing:
            if invite['group_identifier'] == str(self.scim_group1.scim_id):
                assert 2 == len(invite['member_invites'])
                assert 1 == len(invite['owner_invites'])
            elif invite['group_identifier'] == str(self.scim_group2.scim_id):
                assert 1 == len(invite['member_invites'])
                assert 0 == len(invite['owner_invites'])
            else:
                assert False, 'Unknown group scim_id in outgoing invites'

    def test_incoming_invites(self):
        response = self.browser.get('/invites/incoming')
        assert 302 == response.status_code  # Redirect to token service

        self._invite_setup()

        # Check incoming invites as test_user2
        with self.session_cookie(self.browser, self.test_user2.eppn) as client:
            response = client.get('/invites/incoming', content_type=self.content_type_json)
        self._check_success_response(response, type_='GET_GROUP_INVITE_INVITES_INCOMING_SUCCESS')
        payload = response.json.get('payload')
        assert payload.get('outgoing') is None
        incoming = payload['incoming']
        assert 2 == len(incoming)
        for invite in incoming:
            assert str(self.scim_group1.scim_id) == invite['group_identifier']
            assert self.scim_group1.display_name == invite['display_name']
            assert self.test_user2.mail_addresses.primary.email == invite['email_address']
            assert 1 == len(invite['owners'])
            assert invite['role'] is not None

        # Check incoming invites as test_user3
        with self.session_cookie(self.browser, self.test_user3.eppn) as client:
            response = client.get('/invites/incoming', content_type=self.content_type_json)
        self._check_success_response(response, type_='GET_GROUP_INVITE_INVITES_INCOMING_SUCCESS')
        payload = response.json.get('payload')
        assert payload.get('outgoing') is None
        incoming = payload['incoming']
        assert 2 == len(incoming)
        for invite in incoming:
            assert invite['group_identifier'] is not None
            assert invite['display_name'] is not None
            assert self.test_user3.mail_addresses.primary.email == invite['email_address']
            assert 1 == len(invite['owners'])
            assert GroupRole.MEMBER.value == invite['role']

    def test_get_all_data(self):
        response = self.browser.get('/all-data')
        assert 302 == response.status_code  # Redirect to token service

        self._invite_setup()

        # Test with owner and invited
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get('/all-data', content_type=self.content_type_json)
        self._check_success_response(response, type_='GET_GROUP_MANAGEMENT_ALL_DATA_SUCCESS')
        payload = response.json.get('payload')
        assert 2 == len(payload['outgoing'])
        assert 2 == len(payload['owner_of'])

        # Accept member invite as test user 2
        self._accept_invite(
            group_scim_id=str(self.scim_group1.scim_id),
            invitee=self.test_user2,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='member',
        )

        # Test with member and invitee
        with self.session_cookie(self.browser, self.test_user2.eppn) as client:
            response = client.get('/all-data', content_type=self.content_type_json)
        self._check_success_response(response, type_='GET_GROUP_MANAGEMENT_ALL_DATA_SUCCESS')
        payload = response.json.get('payload')
        assert 1 == len(payload['incoming'])
        assert 1 == len(payload['member_of'])

    def test_get_all_data_privacy(self):
        # Add test user as group member and owner, add test user 2 as member
        graph_user1 = GraphUser(
            identifier=str(self.scim_user1.scim_id), display_name=self.test_user.mail_addresses.primary.email
        )
        graph_user2 = GraphUser(
            identifier=str(self.scim_user2.scim_id), display_name=self.test_user2.mail_addresses.primary.email
        )
        self.scim_group1.members = [graph_user1, graph_user2]
        self.scim_group1.owners = [graph_user1]
        self.app.scimapi_groupdb.save(self.scim_group1)

        # Invite test user 2 as owner
        self._invite(
            group_scim_id=str(self.scim_group1.scim_id),
            inviter=self.test_user,
            invite_address=self.test_user2.mail_addresses.primary.email,
            role='owner',
        )

        # Get all data as test user 1
        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            response = client.get('/all-data')
        self._check_success_response(response, type_='GET_GROUP_MANAGEMENT_ALL_DATA_SUCCESS')
        payload = response.json.get('payload')
        # As member the user only see owners for a group
        assert normalised_data(
            [
                {
                    'display_name': 'Test Group 1',
                    'identifier': '00000000-0000-0000-0000-000000000002',
                    'members': [],
                    'owners': [
                        {'display_name': 'johnsmith@example.com', 'identifier': '00000000-0000-0000-0000-000000000000'}
                    ],
                }
            ]
        ) == normalised_data(payload['member_of'])
        # As owner the user see both members and owners
        assert normalised_data(
            [
                {
                    'display_name': 'Test Group 1',
                    'identifier': '00000000-0000-0000-0000-000000000002',
                    'members': [
                        {'display_name': 'johnsmith@example.com', 'identifier': '00000000-0000-0000-0000-000000000000'},
                        {
                            'display_name': 'johnsmith2@example.com',
                            'identifier': '00000000-0000-0000-0000-000000000001',
                        },
                    ],
                    'owners': [
                        {'display_name': 'johnsmith@example.com', 'identifier': '00000000-0000-0000-0000-000000000000'}
                    ],
                }
            ]
        ) == normalised_data(payload['owner_of'])
        # As owner the user see your outgoing invites
        assert normalised_data(
            [
                {
                    'group_identifier': '00000000-0000-0000-0000-000000000002',
                    'member_invites': [],
                    'owner_invites': [{'email_address': 'johnsmith2@example.com'}],
                }
            ]
        ) == normalised_data(payload['outgoing'])
        # test user 1 does not have any incoming invites
        assert [] == normalised_data(payload['incoming'])

        # Get all data as test user 2
        with self.session_cookie(self.browser, self.test_user2.eppn) as client:
            response = client.get('/all-data')
        self._check_success_response(response, type_='GET_GROUP_MANAGEMENT_ALL_DATA_SUCCESS')
        payload = response.json.get('payload')
        # As member the user only see owners for a group
        assert normalised_data(
            [
                {
                    'display_name': 'Test Group 1',
                    'identifier': '00000000-0000-0000-0000-000000000002',
                    'members': [],
                    'owners': [
                        {'display_name': 'johnsmith@example.com', 'identifier': '00000000-0000-0000-0000-000000000000'}
                    ],
                }
            ]
        ) == normalised_data(payload['member_of'])
        # test user 2 is not an owner of a group
        assert [] == payload['owner_of']
        # test user 2 does not have any outgoing invites
        assert [] == payload['outgoing']
        # as an invitee the user see incoming invites
        assert normalised_data(
            [
                {
                    'display_name': 'Test Group 1',
                    'email_address': 'johnsmith2@example.com',
                    'group_identifier': '00000000-0000-0000-0000-000000000002',
                    'owners': [
                        {'display_name': 'johnsmith@example.com', 'identifier': '00000000-0000-0000-0000-000000000000'}
                    ],
                    'role': 'owner',
                }
            ]
        ) == normalised_data(payload['incoming'])
