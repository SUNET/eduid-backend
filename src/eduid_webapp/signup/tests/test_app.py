# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# Copyright (c) 2018 SUNET
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

import json
from contextlib import contextmanager
from mock import patch

from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.signup.app import signup_init_app
from eduid_webapp.signup.verifications import send_verification_mail


class SignupTests(EduidAPITestCase):

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropiate flask
        app for this test case.
        """
        return signup_init_app('signup', config)

    def update_config(self, config):
        config.update({
            'AVAILABLE_LANGUAGES': {'en': 'English','sv': 'Svenska'},
            'DASHBOARD_URL': '/profile/',
            'SIGNUP_URL': 'https://localhost/',
            'DEVELOPMENT': 'DEBUG',
            'APPLICATION_ROOT': '/',
            'LOG_LEVEL': 'DEBUG',
            'AM_BROKER_URL': 'amqp://eduid:eduid_pw@rabbitmq/am',
            'MSG_BROKER_URL': 'amqp://eduid:eduid_pw@rabbitmq/msg',
            'PASSWORD_LENGTH': '10',
            'VCCS_URL': 'http://turq:13085/',
            'TOU_VERSION': '2018-v1',
            'SIGNUP_AND_AUTHN_SHARED_KEY': 'shared_secret_Eifool0ua0eiph7ooc',
            'DEFAULT_FINISH_URL': 'https://www.eduid.se/',
            'RECAPTCHA_PUBLIC_KEY': '',  # disable recaptcha verification
            'RECAPTCHA_PRIVATE_KEY': 'XXXX',
            'STUDENTS_LINK': 'https://www.eduid.se/index.html',
            'TECHNICIANS_LINK': 'https://www.eduid.se/tekniker.html',
            'STAFF_LINK': 'https://www.eduid.se/personal.html',
            'FAQ_LINK': 'https://www.eduid.se/faq.html',
            'CELERY_CONFIG': {
                'CELERY_RESULT_BACKEND': 'amqp',
                'CELERY_TASK_SERIALIZER': 'json',
                'MONGO_URI': config['MONGO_URI'],
            },
        })
        return config

    def init_data(self):
        test_user_dict = self.app.private_userdb.UserClass(data=self.test_user.to_dict())
        self.app.private_userdb.save(test_user_dict, check_sync=False)

    @contextmanager
    def session_cookie(self, client, server_name='localhost'):
        with client.session_transaction() as sess:
            sess.persist()
        client.set_cookie(server_name, key=self.app.config.get('SESSION_COOKIE_NAME'), value=sess._session.token)
        yield client

    def test_get_config(self):

        with self.session_cookie(self.browser) as client:
            response2 = client.get('/config')

            self.assertEqual(response2.status_code, 200)

            config_data = json.loads(response2.data)

            self.assertEqual('GET_SIGNUP_CONFIG_SUCCESS', config_data['type'])
            self.assertEqual(None, config_data['error'])
            self.assertEqual('/profile/',
                    config_data['payload']['dashboard_url'])
            self.assertEqual('test tou english', config_data['payload']['tous']['en'])
            self.assertEqual('test tou svenska', config_data['payload']['tous']['sv'])
            self.assertEqual(True, config_data['payload']['debug'])
            self.assertEqual({u'en': u'English', u'sv': u'Svenska'},
                    config_data['payload']['available_languages'])
            self.assertEqual('https://www.eduid.se/tekniker.html',
                    config_data['payload']['technicians_link'])
            self.assertEqual('https://www.eduid.se/personal.html',
                    config_data['payload']['staff_link'])

    def test_captcha_no_data_fail(self):
        email = 'dummy@example.com'
        with self.session_cookie(self.browser) as client:
            response = client.post('/trycaptcha')
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertEqual(data['error'], True)
            self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_captcha_new(self, mock_sendmail):
        mock_sendmail.return_value = True

        email = 'dummy@example.com'
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'email': email,
                        'recaptcha_response': 'dummy',
                        'tou_accepted': True,
                        'csrf_token': sess.get_csrf_token()
                        }
                response = client.post('/trycaptcha', data=json.dumps(data),
                                       content_type=self.content_type_json)

                data = json.loads(response.data)
                self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_SUCCESS')
                self.assertEqual(data['payload']['next'], 'new')

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_captcha_resend(self, mock_sendmail):
        mock_sendmail.return_value = True

        email = 'dummy@example.com'
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'email': email,
                        'recaptcha_response': 'dummy',
                        'tou_accepted': True,
                        'csrf_token': sess.get_csrf_token()
                        }
                response = client.post('/trycaptcha', data=json.dumps(data),
                                       content_type=self.content_type_json)

        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'email': email,
                        'recaptcha_response': 'dummy',
                        'tou_accepted': True,
                        'csrf_token': sess.get_csrf_token()
                        }
                response = client.post('/trycaptcha', data=json.dumps(data),
                                       content_type=self.content_type_json)

                data = json.loads(response.data)
                self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_SUCCESS')
                self.assertEqual(data['payload']['next'], 'resend-code')

    def test_captcha_used(self):
        email = 'johnsmith@example.com'
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'email': email,
                        'recaptcha_response': 'dummy',
                        'tou_accepted': True,
                        'csrf_token': sess.get_csrf_token()
                        }
                response = client.post('/trycaptcha', data=json.dumps(data),
                                       content_type=self.content_type_json)

                data = json.loads(response.data)
                self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')
                self.assertEqual(data['payload']['next'], 'address-used')

    def test_captcha_no_email(self):
        email = 'dummy@example.com'
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'email': '',
                        'recaptcha_response': 'dummy',
                        'tou_accepted': True,
                        'csrf_token': sess.get_csrf_token()
                        }
                response = client.post('/trycaptcha', data=json.dumps(data),
                                       content_type=self.content_type_json)

                data = json.loads(response.data)
                self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')

    def test_captcha_no_tou(self):
        email = 'dummy@example.com'
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'email': email,
                        'recaptcha_response': 'dummy',
                        'tou_accepted': False,
                        'csrf_token': sess.get_csrf_token()
                        }
                response = client.post('/trycaptcha', data=json.dumps(data),
                                       content_type=self.content_type_json)

                data = json.loads(response.data)
                self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_resend_email(self, mock_sendmail):
        mock_sendmail.return_value = True

        email = 'dummy@example.com'
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'email': email,
                        'csrf_token': sess.get_csrf_token()
                        }
                response = client.post('/resend-verification', data=json.dumps(data),
                                       content_type=self.content_type_json)

                data = json.loads(response.data)
                self.assertEqual(data['type'],
                        'POST_SIGNUP_RESEND_VERIFICATION_SUCCESS')

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('vccs_client.VCCSClient.add_credentials')
    def test_verify_code(self, mock_add_credentials, mock_request_user_sync, mock_sendmail):
        mock_add_credentials.return_value = True
        mock_request_user_sync.return_value = True
        mock_sendmail.return_value = True
        email = 'dummy@example.com'
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    send_verification_mail(email)
                    signup_user = self.app.private_userdb.get_user_by_pending_mail_address(email)
                    response = client.get('/verify-link/' + signup_user.pending_mail_address.verification_code)

                    data = json.loads(response.data)
                    self.assertEqual(data['type'],
                            'GET_SIGNUP_VERIFY_LINK_SUCCESS')
                    self.assertEqual(data['payload']['status'],
                            'verified')

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('vccs_client.VCCSClient.add_credentials')
    def test_verify_non_existing_code(self, mock_add_credentials, mock_request_user_sync, mock_sendmail):
        mock_add_credentials.return_value = True
        mock_request_user_sync.return_value = True
        mock_sendmail.return_value = True

        email = 'dummy@example.com'
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    send_verification_mail(email)
                    response = client.get('/verify-link/' + 'dummy')

                    data = json.loads(response.data)
                    self.assertEqual(data['type'],
                            'GET_SIGNUP_VERIFY_LINK_FAIL')
                    self.assertEqual(data['payload']['status'],
                            'unknown-code')

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('vccs_client.VCCSClient.add_credentials')
    def test_verify_existing_email(self, mock_add_credentials, mock_request_user_sync, mock_sendmail):
        mock_add_credentials.return_value = True
        mock_request_user_sync.return_value = True
        mock_sendmail.return_value = True

        email = 'johnsmith@example.com'
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    send_verification_mail(email)
                    signup_user = self.app.private_userdb.get_user_by_pending_mail_address(email)
                    response = client.get('/verify-link/' + signup_user.pending_mail_address.verification_code)

                    data = json.loads(response.data)
                    self.assertEqual(data['type'],
                            'GET_SIGNUP_VERIFY_LINK_FAIL')
                    self.assertEqual(data['payload']['status'],
                            'already-verified')

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('vccs_client.VCCSClient.add_credentials')
    def test_verify_code_remove_previous(self, mock_add_credentials, mock_request_user_sync, mock_sendmail):
        mock_add_credentials.return_value = True
        mock_request_user_sync.return_value = True
        mock_sendmail.return_value = True

        email = 'dummy@example.com'

        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'email': email,
                        'recaptcha_response': 'dummy',
                        'tou_accepted': True,
                        'csrf_token': sess.get_csrf_token()
                        }
                    client.post('/trycaptcha', data=json.dumps(data),
                                       content_type=self.content_type_json)

                    send_verification_mail(email)
                    signup_user = self.app.private_userdb.get_user_by_pending_mail_address(email)
                    response = client.get('/verify-link/' + signup_user.pending_mail_address.verification_code)

                    data = json.loads(response.data)
                    self.assertEqual(data['type'],
                            'GET_SIGNUP_VERIFY_LINK_SUCCESS')

    def test_get_tous(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                response = client.get('/get-tous')

                data = json.loads(response.data)
                self.assertEqual(data['type'],
                        'GET_SIGNUP_GET_TOUS_SUCCESS')
                self.assertEqual(data['payload']['en'],
                        'test tou english')
                self.assertEqual(data['payload']['sv'],
                        'test tou svenska')
