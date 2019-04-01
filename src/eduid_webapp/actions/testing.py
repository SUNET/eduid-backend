# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 NORDUnet A/S
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
from __future__ import absolute_import

import time
from hashlib import sha256
from copy import deepcopy
from contextlib import contextmanager
from bson import ObjectId
from datetime import datetime
from mock import MagicMock

from eduid_userdb.userdb import User
from eduid_userdb.testing import MOCKED_USER_STANDARD
from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.actions.app import actions_init_app
from eduid_action.common.action_abc import ActionPlugin


class MockIdPApp:

    class Config:
        def __init__(self, **kwargs):
            for key, val in kwargs.items():
                setattr(self, key, val)

    class Logger:
        debug = MagicMock()
        warning = MagicMock()
        error = MagicMock()

    class Authn:
        def log_authn(self, user, success, failure):
            pass

    def __init__(self, actions_db, **kwargs):
        self.config = self.Config(**kwargs)
        self.logger = self.Logger()
        self.actions_db = actions_db
        self.authn = self.Authn()


class TestingActionPlugin(ActionPlugin):

    def get_number_of_steps(self):
        return 1

    def get_url_for_bundle(self, action):
        if 'action_error' in action.to_dict()['params']:
            raise self.ActionError('test error')
        return "http://example.com/plugin.js"

    def get_config_for_bundle(self, action):
        if 'action_error' in action.to_dict()['params']:
            raise self.ActionError('test error')
        return {'setting1': 'dummy'}

    def perform_step(self, action):
        if 'action_error' in action.to_dict()['params']:
            raise self.ActionError('test error')
        if 'rm_action' in action.to_dict()['params']:
            raise self.ActionError('test error', rm=True)
        if 'validation_error' in action.to_dict()['params']:
            raise self.ValidationError({'field1': 'field test error'})
        return {'completed': 'done'}


DUMMY_ACTION = {
    '_id': ObjectId('234567890123456789012301'),
    'eppn': 'hubba-bubba',
    'action': 'dummy',
    'preference': 100, 
    'params': {
    }
}

TEST_CONFIG = {
    'AVAILABLE_LANGUAGES': {'en': 'English','sv': 'Svenska'},
    'DASHBOARD_URL': '/profile/',
    'DEVELOPMENT': 'DEBUG',
    'APPLICATION_ROOT': '/',
    'LOG_LEVEL': 'DEBUG',
    'TOKEN_LOGIN_SHARED_KEY': 'shared_secret_Eifool0ua0eiph7ooc',
    'IDP_URL': 'https://example.com/idp',
    'INTERNAL_SIGNUP_URL': 'https://example.com/signup',
    'PRESERVE_CONTEXT_ON_EXCEPTION': False,
    'BUNDLES_URL': 'http://example.com/bundles/',
    'DEBUG': False,
    'DEVEL_MODE': True
}


class ActionsTestCase(EduidAPITestCase):

    def setUp(self, init_am=True, users=None, copy_user_to_private=False, am_settings=None):
        super(ActionsTestCase, self).setUp(init_am=True, users=None, copy_user_to_private=False, am_settings=None)
        user_data = deepcopy(MOCKED_USER_STANDARD)
        user_data['modified_ts'] = datetime.utcnow()
        self.user = User(data=user_data)
        self.app.central_userdb.save(self.user, check_sync=False)
        self.test_eppn = 'hubba-bubba'

    def tearDown(self):
        self.app.central_userdb._drop_whole_collection()
        self.app.actions_db._drop_whole_collection()
        super(ActionsTestCase, self).tearDown()

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return actions_init_app('actions', config)

    def update_actions_config(self, config):
        """
        to be overridden by child classes, where they can provide additional
        settings specific for the particular plugins to be tested.
        """
        return config

    def update_config(self, config):
        more_config = self.update_actions_config(deepcopy(TEST_CONFIG))
        config.update(more_config)
        return config

    @contextmanager
    def session_cookie(self, client, server_name='localhost'):
        with client.session_transaction() as sess:
            client.set_cookie(server_name, key=self.app.config.get('SESSION_COOKIE_NAME'), value=sess._session.token)
        yield client

    def prepare_session(self, client, action_dict=None, rm_action=False, validation_error=False, action_error=False,
                        total_steps=1, current_step=1, add_action=True, idp_session='dummy-session', set_plugin=True,
                        plugin_name='dummy', plugin_class=TestingActionPlugin):
        if action_dict is None:
            action_dict = deepcopy(DUMMY_ACTION)
        if action_error:
            action_dict['params']['action_error'] = True
        if rm_action:
            action_dict['params']['rm_action'] = True
        if validation_error:
            action_dict['params']['validation_error'] = True
        if add_action:
            self.app.actions_db.add_action(data=deepcopy(action_dict))
        action_dict['_id'] = str(action_dict['_id'])
        with client.session_transaction() as sess:
            sess['eppn'] = str(action_dict['eppn'])
            sess['current_action'] = action_dict
            sess['current_plugin'] = plugin_name
            sess['idp_session'] = idp_session
            sess['current_step'] = current_step
            sess['total_steps'] = total_steps
        if set_plugin:
            self.app.plugins[plugin_name] = plugin_class

    def authenticate(self, client, sess, shared_key=None, idp_session=None):
        eppn = self.test_eppn
        nonce = 'dummy-nonce-xxxx'
        timestamp = str(hex(int(time.time())))
        if shared_key is None:
            shared_key = self.app.config.get('TOKEN_LOGIN_SHARED_KEY')
        data = '{0}|{1}|{2}|{3}'.format(shared_key, eppn, nonce, timestamp)
        hashed = sha256(data.encode('ascii'))
        token = hashed.hexdigest()
        url = '/?eppn={}&token={}&nonce={}&ts={}'.format(eppn,
                                                         token,
                                                         nonce,
                                                         timestamp)
        if idp_session is not None:
            url = '{}&session={}'.format(url, idp_session)
        response = client.get(url)
        return response

    def prepare(self, client, plugin_class, plugin_name, **kwargs):
        self.prepare_session(client, plugin_name=plugin_name,
                             plugin_class=plugin_class, **kwargs)
