# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 SUNET
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
import time
from base64 import b64encode

from flask import url_for
from mock import patch

from eduid_common.api.exceptions import MsgTaskFailed
from eduid_common.api.testing import EduidAPITestCase
from eduid_common.authn.testing import TestVCCSClient
from eduid_webapp.reset_password.app import init_reset_password_app
from eduid_webapp.reset_password.settings.common import ResetPasswordConfig
from eduid_webapp.reset_password.helpers import hash_password, check_password
from eduid_webapp.reset_password.helpers import generate_suggested_password
from eduid_webapp.reset_password.helpers import get_extra_security_alternatives
from eduid_webapp.reset_password.helpers import send_verify_phone_code

__author__ = 'eperez'


class ResetPasswordTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        self.test_user_eppn = 'hubba-bubba'
        self.test_user_email = 'johnsmith@example.com'
        super(ResetPasswordTests, self).setUp()

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_reset_password_app('testing', config)

    def update_config(self, config):
        config.update({
            'available_languages': {'en': 'English', 'sv': 'Svenska'},
            'msg_broker_url': 'amqp://dummy',
            'am_broker_url': 'amqp://dummy',
            'celery_config': {
                'result_backend': 'amqp',
                'task_serializer': 'json'
            },
            'vccs_url': 'http://vccs',
            'email_code_timeout': 7200,
            'phone_code_timeout': 600,
            'password_entropy': 25,
            'no_authn_urls': [r'/reset.*']
        })
        return ResetPasswordConfig(**config)

    def tearDown(self):
        super(ResetPasswordTests, self).tearDown()
        with self.app.app_context():
            self.app.central_userdb._drop_whole_collection()

    def test_app_starts(self):
        self.assertEquals(self.app.config.app_name, "reset_password") 

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_post_email_address(self, mock_sendmail):
        mock_sendmail.return_value = True
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
            self.assertEqual(state.email_address, 'johnsmith@example.com')

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_post_unknown_email_address(self, mock_sendmail):
        mock_sendmail.return_value = True
        with self.app.test_client() as c:
            data = {
                'email': 'unknown@unplaced.un'
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_FAIL')
            self.assertEqual(response.json['payload']['message'], 'resetpw.user-not-found')

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_post_reset_code(self, mock_sendmail):
        mock_sendmail.return_value = True
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
            url = url_for('reset_password.config_reset_pw',
                           _external=True)
            data = {
                'code': state.email_code.code
            }
            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)
            self.assertEquals(response.json['payload']['extra_security']['phone_numbers'][0],
                              'XXXXXXXXXX09')
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_CONFIG_SUCCESS')

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_post_reset_wrong_code(self, mock_sendmail):
        mock_sendmail.return_value = True
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
            url = url_for('reset_password.config_reset_pw',
                           _external=True)
            data = {
                'code': 'wrong-code'
            }
            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)
            self.assertEquals(response.json['payload']['message'], 'resetpw.unknown-code')
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_CONFIG_FAIL')

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_post_reset_code_no_extra_sec(self, mock_sendmail):
        mock_sendmail.return_value = True
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)

            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
            user = self.app.central_userdb.get_user_by_eppn(state.eppn)
            # Unverify phone numbers
            for number in user.phone_numbers.verified.to_list():
                user.phone_numbers.remove(number.key)
            self.app.central_userdb.save(user)
            url = url_for('reset_password.config_reset_pw', _external=True)
            data = {
                'code': state.email_code.code
            }
            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)
            self.assertEquals(response.json['payload']['extra_security'], {})
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_CONFIG_SUCCESS')

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_post_reset_password(self, mock_request_user_sync, mock_sendmail, mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)

            # check that the user has verified data
            user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
            verified_phone_numbers = user.phone_numbers.verified.to_list()
            self.assertEquals(len(verified_phone_numbers), 1)
            verified_nins = user.nins.verified.to_list()
            self.assertEquals(len(verified_nins), 2)

            with c.session_transaction() as session:
                new_password = generate_suggested_password()
                session.reset_password.generated_password_hash = hash_password(new_password)
                url = url_for('reset_password.set_new_pw', _external=True)
                data = {
                    'code': state.email_code.code,
                    'password': new_password
                }

            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SUCCESS')

            # check that the user no longer has verified data
            user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
            verified_phone_numbers = user.phone_numbers.verified.to_list()
            self.assertEquals(len(verified_phone_numbers), 0)
            verified_nins = user.nins.verified.to_list()
            self.assertEquals(len(verified_nins), 0)

            # check that the password is marked as generated
            self.assertTrue(user.credentials.to_list()[0].is_generated)

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_post_reset_password_wrong_code(self, mock_request_user_sync, mock_sendmail, mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)

            # check that the user has verified data
            user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
            verified_phone_numbers = user.phone_numbers.verified.to_list()
            self.assertEquals(len(verified_phone_numbers), 1)
            verified_nins = user.nins.verified.to_list()
            self.assertEquals(len(verified_nins), 2)

            with c.session_transaction() as session:
                new_password = generate_suggested_password()
                session.reset_password.generated_password_hash = hash_password(new_password)
                url = url_for('reset_password.set_new_pw', _external=True)
                data = {
                    'code': 'wrong-code',
                    'password': new_password
                }

            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_NEW_PASSWORD_FAIL')
            self.assertEqual(response.json['payload']['message'], 'resetpw.unknown-code')

            # check that the user still has verified data
            user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
            verified_phone_numbers = user.phone_numbers.verified.to_list()
            self.assertEquals(len(verified_phone_numbers), 1)
            verified_nins = user.nins.verified.to_list()
            self.assertEquals(len(verified_nins), 2)

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_post_reset_password_custom(self, mock_request_user_sync, mock_sendmail, mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)

            with c.session_transaction() as session:
                new_password = generate_suggested_password()
                session.reset_password.generated_password_hash = hash_password(new_password)
                url = url_for('reset_password.set_new_pw', _external=True)
                data = {
                    'code': state.email_code.code,
                    'password': 'cust0m-p4ssw0rd'
                }

            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)

            self.assertEqual(response.status_code, 200)
            user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
            self.assertFalse(user.credentials.to_list()[0].is_generated)

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def test_post_choose_extra_sec(self, mock_sendsms, mock_request_user_sync, mock_sendmail, mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)

            url = url_for('reset_password.config_reset_pw', _external=True)
            data = {
                'code': state.email_code.code
            }
            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)

            url = url_for('reset_password.choose_extra_security', _external=True)
            data = {
                'code': state.email_code.code,
                'phone_index': '0'
            }

            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_EXTRA_SECURITY_SUCCESS')

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def test_post_choose_extra_sec_wrong_code(self, mock_sendsms, mock_request_user_sync, mock_sendmail, mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)

            url = url_for('reset_password.config_reset_pw', _external=True)
            data = {
                'code': 'wrong-code'
            }
            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)

            url = url_for('reset_password.choose_extra_security', _external=True)
            data = {
                'code': state.email_code.code,
                'phone_index': '0'
            }

            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_EXTRA_SECURITY_FAIL')

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def test_post_reset_password_secure(self, mock_sendsms, mock_request_user_sync, mock_sendmail, mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)

            user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
            alternatives = get_extra_security_alternatives(user)
            state.extra_security = alternatives
            state.email_code.is_verified = True
            self.app.password_reset_state_db.save(state)
            phone_number = state.extra_security['phone_numbers'][0]
            send_verify_phone_code(state, phone_number)

            with c.session_transaction() as session:
                new_password = generate_suggested_password()
                session.reset_password.generated_password_hash = hash_password(new_password)
                url = url_for('reset_password.set_new_pw_extra_security', _external=True)
                state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
                data = {
                    'code': state.email_code.code,
                    'phone_code': state.phone_code.code,
                    'password': new_password
                }

            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_SUCCESS')

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def test_post_reset_password_secure_wrong_email_code(self, mock_sendsms, mock_request_user_sync, mock_sendmail, mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)

            user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
            alternatives = get_extra_security_alternatives(user)
            state.extra_security = alternatives
            state.email_code.is_verified = True
            self.app.password_reset_state_db.save(state)
            phone_number = state.extra_security['phone_numbers'][0]
            send_verify_phone_code(state, phone_number)

            with c.session_transaction() as session:
                new_password = generate_suggested_password()
                session.reset_password.generated_password_hash = hash_password(new_password)
                url = url_for('reset_password.set_new_pw_extra_security', _external=True)
                state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
                data = {
                    'code': 'wrong-code',
                    'phone_code': state.phone_code.code,
                    'password': new_password
                }

            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_FAIL')

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def test_post_reset_password_secure_wrong_phone_code(self, mock_sendsms, mock_request_user_sync, mock_sendmail, mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)

            user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
            alternatives = get_extra_security_alternatives(user)
            state.extra_security = alternatives
            state.email_code.is_verified = True
            self.app.password_reset_state_db.save(state)
            phone_number = state.extra_security['phone_numbers'][0]
            send_verify_phone_code(state, phone_number)

            with c.session_transaction() as session:
                new_password = generate_suggested_password()
                session.reset_password.generated_password_hash = hash_password(new_password)
                url = url_for('reset_password.set_new_pw_extra_security', _external=True)
                state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
                data = {
                    'code': state.phone_code.code,
                    'phone_code': 'wrong-code',
                    'password': new_password
                }

            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_FAIL')

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def test_post_reset_password_secure_email_timeout(self, mock_sendsms, mock_request_user_sync,
                                                      mock_sendmail, mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)

            user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
            alternatives = get_extra_security_alternatives(user)
            state.extra_security = alternatives
            state.email_code.is_verified = True
            self.app.password_reset_state_db.save(state)
            phone_number = state.extra_security['phone_numbers'][0]
            send_verify_phone_code(state, phone_number)

            self.app.config.email_code_timeout = 0

            with c.session_transaction() as session:
                new_password = generate_suggested_password()
                session.reset_password.generated_password_hash = hash_password(new_password)
                url = url_for('reset_password.set_new_pw_extra_security', _external=True)
                state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
                data = {
                    'code': state.email_code.code,
                    'phone_code': state.phone_code.code,
                    'password': new_password
                }

            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_FAIL')
            self.assertEqual(response.json['payload']['message'], 'resetpw.expired-email-code')

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def test_post_reset_password_secure_phone_timeout(self, mock_sendsms, mock_request_user_sync,
                                                      mock_sendmail, mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)

            user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
            alternatives = get_extra_security_alternatives(user)
            state.extra_security = alternatives
            state.email_code.is_verified = True
            self.app.password_reset_state_db.save(state)
            phone_number = state.extra_security['phone_numbers'][0]
            send_verify_phone_code(state, phone_number)

            self.app.config.phone_code_timeout = 0

            with c.session_transaction() as session:
                new_password = generate_suggested_password()
                session.reset_password.generated_password_hash = hash_password(new_password)
                url = url_for('reset_password.set_new_pw_extra_security', _external=True)
                state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
                data = {
                    'code': state.email_code.code,
                    'phone_code': state.phone_code.code,
                    'password': new_password
                }

            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_FAIL')
            self.assertEqual(response.json['payload']['message'], 'resetpw.expired-sms-code')

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def test_post_reset_password_secure_custom(self, mock_sendsms, mock_request_user_sync, mock_sendmail, mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()
        mock_sendsms.return_value = True
        with self.app.test_client() as c:
            data = {
                'email': self.test_user_email
            }
            response = c.post('/reset/', data=json.dumps(data),
                              content_type=self.content_type_json)
            self.assertEqual(response.status_code, 200)

            user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
            state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
            alternatives = get_extra_security_alternatives(user)
            state.extra_security = alternatives
            state.email_code.is_verified = True
            self.app.password_reset_state_db.save(state)
            phone_number = state.extra_security['phone_numbers'][0]
            send_verify_phone_code(state, phone_number)

            with c.session_transaction() as session:
                new_password = generate_suggested_password()
                session.reset_password.generated_password_hash = hash_password(new_password)
                url = url_for('reset_password.set_new_pw_extra_security', _external=True)
                state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
                data = {
                    'code': state.email_code.code,
                    'phone_code': state.phone_code.code,
                    'password': 'other-password'
                }

            response = c.post(url, data=json.dumps(data),
                              content_type=self.content_type_json)

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['type'], 'POST_RESET_PASSWORD_RESET_NEW_PASSWORD_SECURE_SUCCESS')

            # check that the password is marked as generated
            user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
            self.assertFalse(user.credentials.to_list()[0].is_generated)


class ChangePasswordTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        self.test_user_eppn = 'hubba-bubba'
        self.test_user_email = 'johnsmith@example.com'
        self.test_user_nin = '197801011235'
        super(ChangePasswordTests, self).setUp(copy_user_to_private=True)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_reset_password_app('testing', config)

    def update_config(self, config):
        config.update({
            'available_languages': {'en': 'English', 'sv': 'Svenska'},
            'msg_broker_url': 'amqp://dummy',
            'am_broker_url': 'amqp://dummy',
            'celery_config': {
                'result_backend': 'amqp',
                'task_serializer': 'json'
            },
            'vccs_url': 'http://vccs',
            'email_code_timeout': 7200,
            'phone_code_timeout': 600,
            'password_length': 12,
            'password_entropy': 25,
            'chpass_timeout': 600,
        })
        return ResetPasswordConfig(**config)

    def tearDown(self):
        super(ChangePasswordTests, self).tearDown()
        with self.app.app_context():
            self.app.central_userdb._drop_whole_collection()

    def test_app_starts(self):
        self.assertEquals(self.app.config.app_name, "reset_password") 

    def test_get_suggested(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        response = self.browser.get('/suggested-password')
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        with self.session_cookie(self.browser, eppn) as client:

            response2 = client.get('/suggested-password')

            passwd = json.loads(response2.data)
            self.assertEqual(passwd['type'],
                             "GET_CHANGE_PASSWORD_SUGGESTED_PASSWORD_SUCCESS")

    def test_change_passwd_no_data(self):
        response = self.browser.post('/change-password')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.post('/change-password')

            sec_data = json.loads(response2.data)
            self.assertEqual(sec_data['type'],
                             "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL")

    def test_change_passwd_no_reauthn(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                            'csrf_token': sess.get_csrf_token(),
                            'new_password': '1234',
                            'old_password': '5678'
                            }
                response2 = client.post('/change-password', data=json.dumps(data),
                                        content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                sec_data = json.loads(response2.data)
                self.assertEqual(sec_data['type'],
                                 "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL")

    def test_change_passwd_stale(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                sess['reauthn-for-chpass'] = True
                with self.app.test_request_context():
                    data = {
                            'csrf_token': sess.get_csrf_token(),
                            'new_password': '1234',
                            'old_password': '5678'
                            }
                response2 = client.post('/change-password', data=json.dumps(data),
                                        content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                sec_data = json.loads(response2.data)
                self.assertEqual(sec_data['type'],
                                 "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL")

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_change_passwd_no_csrf(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.reset_password.views.change_password.change_password',
                           return_value=True):
                    sess['reauthn-for-chpass'] = int(time.time())
                    data = {
                            'new_password': '1234',
                            'old_password': '5678'
                            }
                    response2 = client.post('/change-password', data=json.dumps(data),
                                            content_type=self.content_type_json)

                    self.assertEqual(response2.status_code, 200)

                    sec_data = json.loads(response2.data)
                    self.assertEqual(sec_data['type'],
                                     "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL")

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_change_passwd_wrong_csrf(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.reset_password.views.change_password.change_password', return_value=True):
                    sess['reauthn-for-chpass'] = int(time.time())
                    data = {
                            'csrf_token': '0000',
                            'new_password': '1234',
                            'old_password': '5678'
                            }
                    response2 = client.post('/change-password', data=json.dumps(data),
                                            content_type=self.content_type_json)

                    sec_data = json.loads(response2.data)
                    self.assertEqual(sec_data['type'],
                                     "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL")

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_change_passwd(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.reset_password.views.change_password.change_password', return_value=True):
                    sess['reauthn-for-chpass'] = int(time.time())
                    with self.app.test_request_context():
                        data = {
                                'csrf_token': sess.get_csrf_token(),
                                'new_password': '1234',
                                'old_password': '5678'
                                }
                    response2 = client.post('/change-password', data=json.dumps(data),
                                            content_type=self.content_type_json)

                    self.assertEqual(response2.status_code, 200)

                    sec_data = json.loads(response2.data)
                    self.assertEqual(sec_data['type'],
                                     "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SUCCESS")

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_get_suggested_and_change(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    with patch('eduid_common.authn.vccs.vccs_client.VCCSClient.add_credentials', return_value=True):
                        with patch('eduid_common.authn.vccs.vccs_client.VCCSClient.revoke_credentials', return_value=True):
                            with patch('eduid_common.authn.vccs.vccs_client.VCCSClient.authenticate', return_value=True):
                                sess['reauthn-for-chpass'] = int(time.time())
                                response2 = client.get('/suggested-password')
                                passwd = json.loads(response2.data)
                                self.assertEqual(passwd['type'],
                                                 'GET_CHANGE_PASSWORD_SUGGESTED_PASSWORD_SUCCESS')
                                password = passwd['payload']['suggested_password']
                                sess.reset_password.generated_password_hash = hash_password(password)
                                sess.persist()
                                data = {
                                        'csrf_token': sess.get_csrf_token(),
                                        'new_password': password,
                                        'old_password': '5678'
                                        }
                                response3 = client.post('/change-password', data=json.dumps(data),
                                                        content_type=self.content_type_json)

        self.assertEqual(response3.status_code, 200)

        sec_data = json.loads(response3.data)
        self.assertEqual(sec_data['type'],
                         "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SUCCESS")

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertTrue(user.credentials.to_list()[-1].is_generated)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_get_suggested_and_change_custom(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    with patch('eduid_common.authn.vccs.vccs_client.VCCSClient.add_credentials', return_value=True):
                        with patch('eduid_common.authn.vccs.vccs_client.VCCSClient.revoke_credentials', return_value=True):
                            with patch('eduid_common.authn.vccs.vccs_client.VCCSClient.authenticate', return_value=True):
                                sess['reauthn-for-chpass'] = int(time.time())
                                response2 = client.get('/suggested-password')
                                passwd = json.loads(response2.data)
                                self.assertEqual(passwd['type'],
                                                 'GET_CHANGE_PASSWORD_SUGGESTED_PASSWORD_SUCCESS')
                                password = passwd['payload']['suggested_password']
                                sess.reset_password.generated_password_hash = hash_password(password)
                                sess.persist()
                                data = {
                                        'csrf_token': sess.get_csrf_token(),
                                        'new_password': 'another-password',
                                        'old_password': '5678'
                                        }
                                response3 = client.post('/change-password', data=json.dumps(data),
                                                        content_type=self.content_type_json)

        self.assertEqual(response3.status_code, 200)

        sec_data = json.loads(response3.data)
        self.assertEqual(sec_data['type'],
                         "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_SUCCESS")

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_get_suggested_and_change_wrong_csrf(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    with patch('eduid_common.authn.vccs.vccs_client.VCCSClient.add_credentials', return_value=True):
                        with patch('eduid_common.authn.vccs.vccs_client.VCCSClient.revoke_credentials', return_value=True):
                            with patch('eduid_common.authn.vccs.vccs_client.VCCSClient.authenticate', return_value=True):
                                sess['reauthn-for-chpass'] = int(time.time())
                                response2 = client.get('/suggested-password')
                                passwd = json.loads(response2.data)
                                self.assertEqual(passwd['type'],
                                                 'GET_CHANGE_PASSWORD_SUGGESTED_PASSWORD_SUCCESS')
                                password = passwd['payload']['suggested_password']
                                sess.reset_password.generated_password_hash = hash_password(password)
                                sess.persist()
                                data = {
                                        'csrf_token': 'wrong-csrf-token',
                                        'new_password': password,
                                        'old_password': '5678'
                                        }
                                response3 = client.post('/change-password', data=json.dumps(data),
                                                        content_type=self.content_type_json)

        self.assertEqual(response3.status_code, 200)

        sec_data = json.loads(response3.data)
        self.assertEqual(sec_data['type'],
                         "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL")

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_get_suggested_and_change_wrong_old_pw(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    with patch('eduid_common.authn.vccs.vccs_client.VCCSClient.add_credentials', return_value=True):
                        with patch('eduid_common.authn.vccs.vccs_client.VCCSClient.revoke_credentials', return_value=True):
                            with patch('eduid_common.authn.vccs.vccs_client.VCCSClient.authenticate', return_value=False):
                                sess['reauthn-for-chpass'] = int(time.time())
                                response2 = client.get('/suggested-password')
                                passwd = json.loads(response2.data)
                                self.assertEqual(passwd['type'],
                                                 'GET_CHANGE_PASSWORD_SUGGESTED_PASSWORD_SUCCESS')
                                password = passwd['payload']['suggested_password']
                                sess.reset_password.generated_password_hash = hash_password(password)
                                sess.persist()
                                data = {
                                        'csrf_token': sess.get_csrf_token(),
                                        'new_password': password,
                                        'old_password': '5678'
                                        }
                                response3 = client.post('/change-password', data=json.dumps(data),
                                                        content_type=self.content_type_json)

        self.assertEqual(response3.status_code, 200)

        sec_data = json.loads(response3.data)
        self.assertEqual(sec_data['type'],
                         "POST_CHANGE_PASSWORD_CHANGE_PASSWORD_FAIL")

        # check that the password is marked as generated
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertFalse(user.credentials.to_list()[-1].is_generated)
