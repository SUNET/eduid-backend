# -*- coding: utf8 -*-#

# Copyright (c) 2015 NORDUnet A/S
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
from __future__ import absolute_import

import json
from datetime import datetime, timedelta
from typing import Optional

from bson import ObjectId
from mock import patch

from eduid_common.session import session
from eduid_userdb.tou import ToUEvent

from eduid_webapp.actions.actions.tou import Plugin
from eduid_webapp.actions.testing import ActionsTestCase, MockIdPContext

__author__ = 'eperez'

TOU_ACTION = {
    '_id': ObjectId('234567890123456789012301'),
    'eppn': 'hubba-bubba',
    'action': 'tou',
    'preference': 100,
    'params': {'version': 'test-version'},
}


class MockRTask(object):
    @staticmethod
    def get(timeout: int):
        return None


def add_actions(idp_app, user, ticket):
    """
    stripped down version of eduid_idp.tou_action.add_actions
    """
    version = idp_app.config.tou_version
    action = idp_app.actions_db.add_action(user.eppn, action_type='tou', preference=100, params={'version': version})
    session['current_plugin'] = 'tou'
    action_d = action.to_dict()
    action_d['_id'] = str(action_d['_id'])
    session['current_action'] = action_d
    session.persist()


class ToUActionPluginTests(ActionsTestCase):
    def setUp(self):
        super(ToUActionPluginTests, self).setUp(am_settings={'ACTION_PLUGINS': ['tou']})
        self.tou_db = self.app.tou_db
        self.reaccept_interval = 94608000  # seconds (3 years)

    def tearDown(self):
        self.tou_db._drop_whole_collection()
        super(ToUActionPluginTests, self).tearDown()

    def update_actions_config(self, config):
        config['environment'] = 'dev'
        config['action_plugins'] = ['tou']
        return config

    def tou_accepted(self, user, version, created_ts=None, modified_ts=None):
        event_id = ObjectId()
        if created_ts is None:
            created_ts = datetime.utcnow()
        user.tou.add(
            ToUEvent.from_dict(
                dict(
                    version=version,
                    created_by='eduid_tou_plugin',
                    created_ts=created_ts,
                    modified_ts=modified_ts,
                    event_id=event_id,
                )
            )
        )
        self.app.central_userdb.save(user, check_sync=False)

    def mock_update_attributes(self, app_name: str, obj_id: str) -> MockRTask:
        private_user = self.app.tou_db.get_user_by_id(obj_id)
        self.request_user_sync(private_user)
        return MockRTask()

    # parameterized test methods

    def _get_tou_action(self):
        """
        Get data on the actions service when there is a ToU action pending.
        """
        mock_idp_app = MockIdPContext(self.app.actions_db, tou_version='test-version')
        with self.app.test_request_context('/get-actions'):
            add_actions(mock_idp_app, self.user, None)
            self.authenticate()
            response = self.app.dispatch_request()
            return json.loads(response)

    def _get_config(self, tou_version: str = 'test-version'):
        """
        Get configuration for the actions front app when there is a pending ToU actions.

        :param tou_version: to control which tou version to look for
        """
        mock_idp_app = MockIdPContext(self.app.actions_db, tou_version=tou_version)
        with self.app.test_request_context('/config'):
            add_actions(mock_idp_app, self.user, None)
            self.authenticate()
            response = self.app.dispatch_request()
            return json.loads(response.data.decode('utf-8'))

    def _post_tou_action(self, post_data: Optional[dict] = None):
        """
        POST the results of the user's actions in response to a ToU acceptance request.

        :param post_data: to control the contents of the POSTed data.
        """
        with self.session_cookie(self.browser) as client:
            self.prepare(client, Plugin, 'tou', action_dict=TOU_ACTION)
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {'accept': True, 'csrf_token': sess.get_csrf_token()}
                    if post_data is not None:
                        data.update(post_data)
                    return client.post('/post-action', data=json.dumps(data), content_type=self.content_type_json)

    # actual tests

    def test_get_tou_action(self):
        data = self._get_tou_action()
        self.assertEqual(data['action'], True)
        self.assertEqual('http://example.com/bundles/eduid_action.tou-bundle.dev.js', data['url'])

    def test_get_config(self):
        data = self._get_config()
        self.assertEqual(data['payload']['tous']['sv'], 'test tou svenska')

    def test_get_config_no_tous(self):
        data = self._get_config(tou_version='not-existing-version')
        self.assertEqual(data['payload']['message'], 'tou.no-tou')

    @patch('eduid_am.tasks.update_attributes_keep_result.delay')
    def test_get_accept_tou(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.mock_update_attributes
        #  verify the user hasn't previously accepted the test version
        user = self.app.central_userdb.get_user_by_eppn(self.user.eppn)
        self.assertFalse(
            user.tou.has_accepted(TOU_ACTION['params']['version'], reaccept_interval=self.reaccept_interval)
        )
        post_data = {'accept': True}
        response = self._post_tou_action(post_data)
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertEqual(response_data['payload']['message'], 'actions.action-completed')

        # verify the tou is now accepted in the main database
        user = self.app.central_userdb.get_user_by_eppn(self.user.eppn)
        self.assertTrue(
            user.tou.has_accepted(TOU_ACTION['params']['version'], reaccept_interval=self.reaccept_interval)
        )

    @patch('eduid_am.tasks.update_attributes_keep_result.delay')
    def test_reaccept_tou_no_modified_ts(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.mock_update_attributes
        #  verify the users previous ToU acceptance has expired

        user = self.app.central_userdb.get_user_by_eppn(self.user.eppn)
        four_years = timedelta(days=1460)
        self.tou_accepted(user, TOU_ACTION['params']['version'], created_ts=datetime.utcnow() - four_years)
        user = self.app.central_userdb.get_user_by_eppn(self.user.eppn)

        self.assertFalse(
            user.tou.has_accepted(TOU_ACTION['params']['version'], reaccept_interval=self.reaccept_interval)
        )

        post_data = {'accept': True}
        response = self._post_tou_action(post_data)
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertEqual(response_data['payload']['message'], 'actions.action-completed')

        # verify the tou is now accepted in the main database
        user = self.app.central_userdb.get_user_by_eppn(self.user.eppn)
        self.assertTrue(
            user.tou.has_accepted(TOU_ACTION['params']['version'], reaccept_interval=self.reaccept_interval)
        )

    @patch('eduid_am.tasks.update_attributes_keep_result.delay')
    def test_reaccept_tou(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.mock_update_attributes
        #  verify the users previous ToU acceptance has expired

        user = self.app.central_userdb.get_user_by_eppn(self.user.eppn)
        four_years = timedelta(days=1460)
        self.tou_accepted(
            user,
            TOU_ACTION['params']['version'],
            created_ts=datetime.utcnow() - four_years,
            modified_ts=datetime.utcnow() - four_years,
        )
        user = self.app.central_userdb.get_user_by_eppn(self.user.eppn)

        self.assertFalse(
            user.tou.has_accepted(TOU_ACTION['params']['version'], reaccept_interval=self.reaccept_interval)
        )

        post_data = {'accept': True}
        response = self._post_tou_action(post_data)
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertEqual(response_data['payload']['message'], 'actions.action-completed')

        # verify the tou is now accepted in the main database
        user = self.app.central_userdb.get_user_by_eppn(self.user.eppn)
        self.assertTrue(
            user.tou.has_accepted(TOU_ACTION['params']['version'], reaccept_interval=self.reaccept_interval)
        )

    def test_get_not_accept_tou(self):
        with self.session_cookie(self.browser) as client:
            self.prepare(client, Plugin, 'tou', action_dict=TOU_ACTION)
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    csrf_token = sess.get_csrf_token()
                data = json.dumps({'accept': False, 'csrf_token': csrf_token})
                response = client.post('/post-action', data=data, content_type=self.content_type_json)
                self.assertEqual(response.status_code, 200)
                data = json.loads(response.data)
                self.assertEqual(data['payload']['message'], 'tou.must-accept')
