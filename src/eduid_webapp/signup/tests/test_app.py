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

from mock import Mock, patch

from eduid_userdb.data_samples import NEW_COMPLETED_SIGNUP_USER_EXAMPLE
from eduid_common.api.testing import EduidAPITestCase

from eduid_webapp.signup.app import signup_init_app
from eduid_webapp.signup.settings.common import SignupConfig
from eduid_webapp.signup.verifications import send_verification_mail


def mock_response(status_code=200, content=None, json_data=None, headers=dict(), raise_for_status=None):
    """
    since we typically test a bunch of different
    requests calls for a service, we are going to do
    a lot of mock responses, so its usually a good idea
    to have a helper function that builds these things
    """
    mock_resp = Mock()
    # mock raise_for_status call w/optional error
    mock_resp.raise_for_status = Mock()
    if raise_for_status:
        mock_resp.raise_for_status.side_effect = raise_for_status
    # set status code and content
    mock_resp.status_code = status_code
    mock_resp.content = content
    # set headers
    mock_resp.headers = headers
    # add json data if provided
    if json_data:
        mock_resp.json = Mock(return_value=json_data)
    return mock_resp


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
                'magic_code': 'magic-code',
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
    def _captcha_new(self, mock_sendmail: Any, mock_recaptcha: Any,
                     data1: Optional[dict] = None,
                     email: str = 'dummy@example.com'):
        """
        Bypass captcha verification using a magic code.

        :param data1: to control the data POSTed to the /trycaptcha endpoint
        :param email: the email to use for registration
        """
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

                    return client.post('/trycaptcha', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def _captcha_new_magic_code(self, mock_sendmail: Any, data1: Optional[dict] = None,
                                email: str = 'dummy+magic-code@example.com'):
        """
        Bypass captcha verification using a magic code.

        :param data1: to control the data POSTed to the /trycaptcha endpoint
        :param email: the email to use for registration
        """
        mock_sendmail.return_value = True

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

                    return client.post('/trycaptcha', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def _resend_email(self, mock_sendmail: Any, mock_recaptcha: Any, data1: Optional[dict] = None, email: str = 'dummy@example.com'):
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
                    data = {
                        'email': email,
                        'csrf_token': sess.get_csrf_token()
                    }
                    if data1 is not None:
                        data.update(data1)

                return client.post(
                    '/resend-verification', data=json.dumps(data), content_type=self.content_type_json
                )

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('vccs_client.VCCSClient.add_credentials')
    def _verify_code(self, mock_add_credentials: Any, mock_request_user_sync: Any, mock_sendmail: Any, mock_recaptcha: Any,
                     code: str = '', magic: bool = False, email: str = 'dummy@example.com'):
        """
        Test the verification link sent by email, possibly using a magic code.

        :param code: the code to use
        :param magic: whether to use the magic code
        :param email: the email address to use
        """
        mock_add_credentials.return_value = True
        mock_request_user_sync.return_value = True
        mock_sendmail.return_value = True
        mock_recaptcha.return_value = True
        if code:
            email = f'dummy+{code}@example.com'
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    send_verification_mail(email)
                    if magic:
                        # send_veridfication_mail does not persist the session by itself (relies on the request cycle)
                        # so at this point the code has been lost from the session
                        signup_user = self.app.private_userdb.get_user_by_pending_mail_address(email)
                        sess.signup.email_verification_code = signup_user.pending_mail_address.verification_code
                        sess.persist()
                    else:
                        signup_user = self.app.private_userdb.get_user_by_pending_mail_address(email)
                        code = signup_user.pending_mail_address.verification_code

                    return client.get('/verify-link/' + code)

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('vccs_client.VCCSClient.add_credentials')
    def _verify_code_after_captcha(self, mock_add_credentials: Any, mock_request_user_sync: Any, mock_sendmail: Any, mock_recaptcha: Any,
                                   data1: Optional[dict] = None, email: str = 'dummy@example.com'):
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

                    send_verification_mail(email)
                    signup_user = self.app.private_userdb.get_user_by_pending_mail_address(email)
                    response = client.get('/verify-link/' + signup_user.pending_mail_address.verification_code)

                    return json.loads(response.data)

    # actual tests

    def test_captcha_new(self):
        response = self._captcha_new()
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_SUCCESS')
        self.assertEqual(data['payload']['next'], 'new')

    def test_captcha_repeated(self):
        response = self._captcha_new(email='johnsmith@example.com')
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')
        self.assertEqual(data['payload']['message'], 'signup.registering-address-used')

    def test_captcha_repeated_unverified(self):
        response = self._captcha_new(email='johnsmith2@example.com')
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

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    def test_captcha_new_magic_code(self, mock_recaptcha: Any):
        mock_recaptcha.return_value = True
        response = self._captcha_new_magic_code()
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_SUCCESS')
        self.assertEqual(data['payload']['next'], 'new')

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    def test_captcha_new_magic_code_pro(self, mock_recaptcha: Any):
        mock_recaptcha.return_value = False
        self.app.config.environment = 'pro'

        response = self._captcha_new_magic_code()
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')
        self.assertEqual(data['payload']['message'], 'signup.recaptcha-not-verified')

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    def test_captcha_new_magic_no_code(self, mock_recaptcha: Any):
        mock_recaptcha.return_value = False
        self.app.config.magic_code = ''

        response = self._captcha_new_magic_code()
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')
        self.assertEqual(data['payload']['message'], 'signup.recaptcha-not-verified')

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    def test_captcha_new_magic_code_wrong(self, mock_recaptcha: Any):
        mock_recaptcha.return_value = False
        response = self._captcha_new_magic_code(email='dummy+magic-code-wrong@example.com')
        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')
        self.assertEqual(data['payload']['message'], 'signup.recaptcha-not-verified')

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    def test_captcha_resend(self, mock_recaptcha: Any):
        mock_recaptcha.return_value = True
        response = self._captcha_new_magic_code()
        response = self._captcha_new_magic_code()

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_SUCCESS')
        self.assertEqual(data['payload']['next'], 'resend-code')

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    def test_captcha_resend_no_magic(self, mock_recaptcha: Any):

        mock_recaptcha.return_value = True
        response = self._captcha_new_magic_code(email='dummy@example.com')

        mock_recaptcha.return_value = False
        response = self._captcha_new_magic_code(email='dummy@example.com')

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')
        self.assertEqual(data['payload']['message'], 'signup.recaptcha-not-verified')

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    def test_captcha_used(self, mock_recaptcha: Any):
        mock_recaptcha.return_value = True
        email = 'johnsmith+magic-code@example.com'
        user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        user.mail_addresses.primary.email = email
        self.app.central_userdb.save(user)
        data = user.to_dict()
        self.app.private_userdb.save(self.app.private_userdb.UserClass(data=data), check_sync=False)

        response = self._captcha_new_magic_code(email=email)

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')
        self.assertEqual(data['payload']['next'], 'address-used')

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    def test_captcha_no_email(self, mock_recaptcha: Any):
        mock_recaptcha.return_value = True
        response = self._captcha_new_magic_code(email='')

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')
        self.assertIn('email', data['payload']['error'])
        self.assertNotIn('recaptcha_response', data['payload']['error'])

    @patch('eduid_webapp.signup.views.verify_recaptcha')
    def test_captcha_no_tou(self, mock_recaptcha: Any):
        mock_recaptcha.return_value = True
        email = 'dummy+magic-code@example.com'
        data1 = {'tou_accepted': False}

        response = self._captcha_new_magic_code(email=email, data1=data1)

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'POST_SIGNUP_TRYCAPTCHA_FAIL')
        self.assertEqual(data['payload']['message'], 'signup.tou-not-accepted')

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

    def test_verify_code_with_magic(self):
        response = self._verify_code(code='magic-code', magic=True)

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'GET_SIGNUP_VERIFY_LINK_SUCCESS')
        self.assertEqual(data['payload']['status'], 'verified')

    def test_verify_code_with_no_magic_in_pro(self):
        self.app.config.environment = 'pro'

        response = self._verify_code(code='magic-code', magic=True)

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'GET_SIGNUP_VERIFY_LINK_FAIL')
        self.assertEqual(data['payload']['status'], 'unknown-code')

    def test_verify_code_with_magic_wrong_code(self):
        response = self._verify_code(code='magic-code-wrong', magic=True)

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'GET_SIGNUP_VERIFY_LINK_FAIL')
        self.assertEqual(data['payload']['status'], 'unknown-code')

    def test_verify_code_with_no_magic_configured(self):
        self.app.config.magic_code = ''
        response = self._verify_code(code='magic-code', magic=True)

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'GET_SIGNUP_VERIFY_LINK_FAIL')
        self.assertEqual(data['payload']['status'], 'unknown-code')

    def test_verify_non_existing_code(self):
        response = self._verify_code(code='dummy', magic=True)

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'GET_SIGNUP_VERIFY_LINK_FAIL')
        self.assertEqual(data['payload']['status'], 'unknown-code')

    def test_verify_existing_email(self):
        response = self._verify_code(email='johnsmith@example.com')

        data = json.loads(response.data)
        self.assertEqual(data['type'], 'GET_SIGNUP_VERIFY_LINK_FAIL')
        self.assertEqual(data['payload']['status'], 'already-verified')

    def test_verify_code_after_captcha(self):
        data = self._verify_code_after_captcha()
        self.assertEqual(data['type'], 'GET_SIGNUP_VERIFY_LINK_SUCCESS')
