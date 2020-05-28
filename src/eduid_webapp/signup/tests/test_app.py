# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# Copyright (c) 2018-2019 SUNET
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
from typing import Any, Optional

from mock import patch

from eduid_common.api.testing import EduidAPITestCase
from eduid_userdb.exceptions import UserOutOfSync

from eduid_webapp.signup.app import signup_init_app
from eduid_webapp.signup.settings.common import SignupConfig
from eduid_webapp.signup.verifications import send_verification_mail


class SignupTests(EduidAPITestCase):
    def setUp(self):
        super(SignupTests, self).setUp(copy_user_to_private=True)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return signup_init_app('signup', config)

    def update_config(self, app_config):
        app_config.update(
            {
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'signup_authn_url': '/services/authn/signup-authn',
                'signup_url': 'https://localhost/',
                'development': 'DEBUG',
                'application_root': '/',
                'log_level': 'DEBUG',
                'am_broker_url': 'amqp://eduid:eduid_pw@rabbitmq/am',
                'msg_broker_url': 'amqp://eduid:eduid_pw@rabbitmq/msg',
                'password_length': '10',
                'vccs_url': 'http://turq:13085/',
                'tou_version': '2018-v1',
                'tou_url': 'https://localhost/get-tous',
                'default_finish_url': 'https://www.eduid.se/',
                'recaptcha_public_key': 'XXXX',
                'recaptcha_private_key': 'XXXX',
                'students_link': 'https://www.eduid.se/index.html',
                'technicians_link': 'https://www.eduid.se/tekniker.html',
                'staff_link': 'https://www.eduid.se/personal.html',
                'faq_link': 'https://www.eduid.se/faq.html',
                'celery_config': {
                    'result_backend': 'amqp',
                    'task_serializer': 'json',
                    'mongo_uri': app_config['mongo_uri'],
                },
                'environment': 'dev',
            }
        )
        return SignupConfig(**app_config)

    @contextmanager
    def session_cookie(self, client, server_name='localhost'):
        with client.session_transaction() as sess:
            sess.persist()
        client.set_cookie(server_name, key=self.app.config.session_cookie_name, value=sess._session.token)
        yield client

    # parameterized test methods

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def _captcha_new(
        self,
        mock_sendmail: Any,
        mock_recaptcha: Any,
        data1: Optional[dict] = None,
        email: str = 'dummy@example.com',
        recaptcha_return_value: bool = True,
        add_magic_cookie: bool = False,
    ):
        """
        :param data1: to control the data POSTed to the /trycaptcha endpoint
        :param email: the email to use for registration
        :param recaptcha_return_value: to mock captcha verification failure
        :param add_magic_cookie: add magic cookie to the trycaptcha request
        """
        mock_sendmail.return_value = True
        mock_recaptcha.return_value = recaptcha_return_value

        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'email': email,
                        'recaptcha_response': 'dummy',
                        'tou_accepted': True,
                        'csrf_token': sess.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)

                    if add_magic_cookie:
                        client.set_cookie(
                            'localhost', key=self.app.config.magic_cookie_name, value=self.app.config.magic_cookie
                        )

                    return client.post('/trycaptcha', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def _resend_email(
        self, mock_sendmail: Any, mock_recaptcha: Any, data1: Optional[dict] = None, email: str = 'dummy@example.com'
    ):
        """
        Trigger re-sending an email with a verification code.

        :param data1: to control the data POSTed to the resend-verification endpoint
        :param email: what email address to use
        """
        mock_sendmail.return_value = True
        mock_recaptcha.return_value = True

        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {'email': email, 'csrf_token': sess.get_csrf_token()}
                    if data1 is not None:
                        data.update(data1)

                return client.post('/resend-verification', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('vccs_client.VCCSClient.add_credentials')
    def _verify_code(
        self,
        mock_add_credentials: Any,
        mock_request_user_sync: Any,
        mock_sendmail: Any,
        mock_recaptcha: Any,
        code: str = '',
        email: str = 'dummy@example.com',
    ):
        """
        Test the verification link sent by email

        :param code: the code to use
        :param email: the email address to use
        """
        mock_add_credentials.return_value = True
        mock_request_user_sync.return_value = True
        mock_sendmail.return_value = True
        mock_recaptcha.return_value = True
        with self.session_cookie(self.browser) as client:
            with client.session_transaction():
                with self.app.test_request_context():
                    send_verification_mail(email)
                    signup_user = self.app.private_userdb.get_user_by_pending_mail_address(email)
                    code = code or signup_user.pending_mail_address.verification_code

                    return client.get('/verify-link/' + code)

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('vccs_client.VCCSClient.add_credentials')
    def _verify_code_after_captcha(
        self,
        mock_add_credentials: Any,
        mock_request_user_sync: Any,
        mock_sendmail: Any,
        mock_recaptcha: Any,
        data1: Optional[dict] = None,
        email: str = 'dummy@example.com',
    ):
        """
        Verify the pending account with an emailed verification code after creating the account by verifying the captcha.

        :param data1: to control the data sent to the trycaptcha endpoint
        :param email: what email address to use
        """
        mock_add_credentials.return_value = True
        mock_request_user_sync.return_value = True
        mock_sendmail.return_value = True
        mock_recaptcha.return_value = True

        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'email': email,
                        'recaptcha_response': 'dummy',
                        'tou_accepted': True,
                        'csrf_token': sess.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)

                    client.post('/trycaptcha', data=json.dumps(data), content_type=self.content_type_json)

                    if data1 is None:
                        send_verification_mail(email)

                    signup_user = self.app.private_userdb.get_user_by_pending_mail_address(email)
                    response = client.get('/verify-link/' + signup_user.pending_mail_address.verification_code)

                    return json.loads(response.data)

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('vccs_client.VCCSClient.add_credentials')
    def _get_code_backdoor(
        self,
        mock_add_credentials: Any,
        mock_request_user_sync: Any,
        mock_sendmail: Any,
        mock_recaptcha: Any,
        email: str,
    ):
        """
        Test getting the generatied verification code through the backdoor
        """
        mock_add_credentials.return_value = True
        mock_request_user_sync.return_value = True
        mock_sendmail.return_value = True
        mock_recaptcha.return_value = True
        with self.session_cookie(self.browser) as client:
            with client.session_transaction():
                with self.app.test_request_context():
                    send_verification_mail(email)

                    client.set_cookie(
                        'localhost', key=self.app.config.magic_cookie_name, value=self.app.config.magic_cookie
                    )
                    return client.get(f'/get-code?email={email}')

    def test_get_code_backdoor(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'dev'

        email = 'johnsmith4@example.com'
        resp = self._get_code_backdoor(email=email)

        signup_user = self.app.private_userdb.get_user_by_pending_mail_address(email)

        self.assertEqual(signup_user.pending_mail_address.verification_code, resp.data.decode('ascii'))

    def test_get_code_no_backdoor_in_pro(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'pro'

        email = 'johnsmith4@example.com'
        resp = self._get_code_backdoor(email=email)

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured1(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = ''
        self.app.config.environment = 'dev'

        email = 'johnsmith4@example.com'
        resp = self._get_code_backdoor(email=email)

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured2(self):
        self.app.config.magic_cookie = ''
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'dev'

        email = 'johnsmith4@example.com'
        resp = self._get_code_backdoor(email=email)

        self.assertEqual(resp.status_code, 400)

    # actual tests

    def test_captcha_new(self):
        response = self._captcha_new()
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_SUCCESS')
        self.assertEqual(data['payload']['next'], 'new')

    def test_captcha_new_no_key(self):
        self.app.config.recaptcha_public_key = None
        response = self._captcha_new()
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')
        self.assertEqual(data['payload']['message'], 'signup.recaptcha-not-verified')

    def test_captcha_new_wrong_csrf(self):
        data1 = {'csrf_token': 'wrong-token'}
        response = self._captcha_new(data1=data1)
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')
        self.assertEqual(data['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    def test_captcha_repeated(self):
        response = self._captcha_new(email='johnsmith@example.com')
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')
        self.assertEqual(data['payload']['message'], 'signup.registering-address-used')

    def test_captcha_remove_repeated_unverified(self):
        response = self._captcha_new(email='johnsmith2@example.com')
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_SUCCESS')
        self.assertEqual(data['payload']['next'], 'new')

    def test_captcha_fail(self):
        response = self._captcha_new(recaptcha_return_value=False)
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')

    def test_captcha_backdoor(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'dev'
        response = self._captcha_new(recaptcha_return_value=False, add_magic_cookie=True)
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_SUCCESS')

    def test_captcha_no_backdoor_in_pro(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'pro'
        response = self._captcha_new(recaptcha_return_value=False, add_magic_cookie=True)
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')

    def test_captcha_no_backdoor_misconfigured1(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = ''
        self.app.config.environment = 'dev'
        response = self._captcha_new(recaptcha_return_value=False, add_magic_cookie=True)
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')

    def test_captcha_no_backdoor_misconfigured2(self):
        self.app.config.magic_cookie = ''
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'dev'
        response = self._captcha_new(recaptcha_return_value=False, add_magic_cookie=True)
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')

    def test_captcha_unsynced(self):
        with patch('eduid_webapp.signup.helpers.save_and_sync_user') as mock_save:
            mock_save.side_effect = UserOutOfSync('unsync')
            response = self._captcha_new()
            data = json.loads(response.data)
            self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_SUCCESS')
            self.assertEqual(data['payload']['next'], 'new')

    def test_captcha_no_data_fail(self):
        with self.session_cookie(self.browser) as client:
            response = client.post('/trycaptcha')
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertEqual(data['error'], True)
            self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')
            self.assertIn('email', data['payload']['error'])
            self.assertIn('csrf_token', data['payload']['error'])
            self.assertIn('recaptcha_response', data['payload']['error'])

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_resend_email(self, mock_sendmail):
        response = self._resend_email()

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_RESEND_VERIFICATION_SUCCESS')

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_resend_email_wrong_csrf(self, mock_sendmail):
        data1 = {'csrf_token': 'wrong-token'}
        response = self._resend_email(data1=data1)

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_RESEND_VERIFICATION_FAIL')
        self.assertEqual(data['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    def test_verify_code(self):
        response = self._verify_code()

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'GET_SIGNUP_VERIFY_LINK_SUCCESS')
        self.assertEqual(data['payload']['status'], 'verified')

    def test_verify_code_unsynced(self):
        with patch('eduid_webapp.signup.helpers.save_and_sync_user') as mock_save:
            mock_save.side_effect = UserOutOfSync('unsync')
            response = self._verify_code()
            data = json.loads(response.data)
            self.assertEqual(data['type'], 'GET_SIGNUP_VERIFY_LINK_FAIL')
            self.assertEqual(data['payload']['message'], 'user-out-of-sync')

    def test_verify_existing_email(self):
        response = self._verify_code(email='johnsmith@example.com')

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'GET_SIGNUP_VERIFY_LINK_FAIL')
        self.assertEqual(data['payload']['status'], 'already-verified')

    def test_verify_code_after_captcha(self):
        data = self._verify_code_after_captcha()
        self.assertEqual(data['type'], 'GET_SIGNUP_VERIFY_LINK_SUCCESS')

    def test_verify_code_after_captcha_proofing_log_error(self):
        from eduid_webapp.signup.verifications import ProofingLogFailure

        with patch('eduid_webapp.signup.views.verify_email_code') as mock_verify:
            mock_verify.side_effect = ProofingLogFailure('fail')
            data = self._verify_code_after_captcha()
            self.assertEqual(data['type'], 'GET_SIGNUP_VERIFY_LINK_FAIL')
            self.assertEqual(data['payload']['message'], 'Temporary technical problems')

    def test_verify_code_after_captcha_wrong_csrf(self):
        with self.assertRaises(AttributeError):
            data1 = {'csrf_token': 'wrong-token'}
            self._verify_code_after_captcha(data1=data1)

    def test_verify_code_after_captcha_dont_accept_tou(self):
        with self.assertRaises(AttributeError):
            data1 = {'tou_accepted': False}
            self._verify_code_after_captcha(data1=data1)
