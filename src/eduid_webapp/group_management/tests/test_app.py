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
#     3. Neither the name of the NORDUnet nor the names of its
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
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from bson import ObjectId

from eduid_common.api.testing import EduidAPITestCase

from eduid_groupdb.group import Group as GraphGroup
from eduid_groupdb.group import User as GraphUser
from eduid_groupdb.testing import Neo4jTemporaryInstance
from eduid_scimapi.groupdb import GroupExtensions, ScimApiGroup
from eduid_scimapi.userdb import ScimApiUser
from eduid_webapp.group_management.app import init_group_management_app
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

    def setUp(self, **kwargs):
        super(GroupManagementTests, self).setUp(**kwargs)
        self.scim_user1 = self._add_scim_user(scim_id=uuid4(), eppn=self.test_user.eppn)
        self.scim_group1 = self._add_scim_group(scim_id=uuid4(), display_name='Test Group 1')

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
            self.app.central_userdb._drop_whole_collection()

    def test_app_starts(self):
        self.assertEquals(self.app.config.app_name, "group_management")

    def test_get_member_groups(self):
        # Add test user as group member
        graph_user = GraphUser(identifier=str(self.scim_user1.scim_id), display_name=self.test_user.display_name)
        self.scim_group1.graph.members = [graph_user]
        self.scim_group1.graph.owners = [graph_user]
        self.app.scimapi_groupdb.graphdb.save(self.scim_group1.graph)

        response = self.browser.get('/groups')
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            response = browser.get('/groups')
        self.assertEqual(response.status_code, 200)  # Authenticated request
        payload = response.json.get('payload')
        self.assertEqual(1, len(payload['member_of']))
        self.assertEqual(1, len(payload['owner_of']))
        self.assertEqual('Test Group 1', payload['member_of'][0]['display_name'])
        self.assertEqual('Test Group 1', payload['owner_of'][0]['display_name'])

    def test_get_member_groups_no_scim_user(self):
        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            response = browser.get('/groups')
        self.assertEqual(response.status_code, 200)  # Authenticated request
        payload = response.json.get('payload')
        self.assertEqual(0, len(payload['member_of']))
        self.assertEqual(0, len(payload['owner_of']))
