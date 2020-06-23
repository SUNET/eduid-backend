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
from datetime import datetime, timedelta
from typing import Any, Optional

from mock import patch

from eduid_common.api.testing import EduidAPITestCase
from eduid_userdb.mail import MailAddress
from eduid_userdb.proofing import EmailProofingElement, EmailProofingState

from eduid_webapp.email.app import email_init_app
from eduid_webapp.email.settings.common import EmailConfig


class EmailTests(EduidAPITestCase):
    def setUp(self):
        super(EmailTests, self).setUp(copy_user_to_private=True)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return email_init_app('emails', config)

    def update_config(self, app_config):
        app_config.update(
            {
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'msg_broker_url': 'amqp://dummy',
                'am_broker_url': 'amqp://dummy',
                'email_verify_redirect_url': '/profile/',
                'celery_config': {
                    'result_backend': 'amqp',
                    'task_serializer': 'json',
                    'mongo_uri': app_config['mongo_uri'],
                },
                'email_verification_timeout': 86400,
                'throttle_resend_seconds': 300,
            }
        )
        return EmailConfig(**app_config)

    def _remove_all_emails(self, user):
        unverified = [address for address in user.mail_addresses.to_list() if not address.is_verified]
        verified = [address for address in user.mail_addresses.to_list() if address.is_verified]
        for address in unverified:
            user.mail_addresses.remove(address.email)
        for address in verified:
            address.is_primary = False
            address.is_verified = False
            user.mail_addresses.remove(address.email)

    def _add_2_emails(self, user):
        verified = MailAddress.from_dict(
            dict(email='verified@example.com', created_by='test', verified=True, primary=True)
        )
        verified2 = MailAddress.from_dict(
            dict(email='verified2@example.com', created_by='test', verified=True, primary=False)
        )
        user.mail_addresses.add(verified)
        user.mail_addresses.add(verified2)

    def _add_2_emails_1_verified(self, user):
        verified = MailAddress.from_dict(
            dict(email='verified@example.com', created_by='test', verified=True, primary=True)
        )
        verified2 = MailAddress.from_dict(
            dict(email='unverified@example.com', created_by='test', verified=False, primary=False)
        )
        user.mail_addresses.add(verified)
        user.mail_addresses.add(verified2)

    # Parameterized test methods

    def _get_all_emails(self):
        """
        GET a list with all the email addresses of the test user
        """
        response = self.browser.get('/all')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/all')

            return json.loads(response2.data)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.email.verifications.get_unique_hash')
    def _post_email(
        self,
        mock_code_verification: Any,
        mock_request_user_sync: Any,
        mock_sendmail: Any,
        data1: Optional[dict] = None,
        send_data: bool = True,
    ):
        """
        POST email data to add new email address to the test user.

        :param data1: to override the data POSTed by default
        :param send_data: whether to actually send data in the POST
        """
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        mock_code_verification.return_value = u'123456'
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                with self.app.test_request_context():
                    data = {
                        'email': 'johnsmith3@example.com',
                        'verified': False,
                        'primary': False,
                        'csrf_token': sess.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)

                if send_data:
                    return client.post('/new', data=json.dumps(data), content_type=self.content_type_json)

                return client.post('/new')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def _post_primary(self, mock_request_user_sync: Any, data1: Optional[dict] = None):
        """
        Choose an email of the test user as primary

        :param data: to control what is sent to the server in the POST
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self.browser.post('/primary')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                with self.app.test_request_context():

                    data = {
                        'csrf_token': sess.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)

                return client.post('/primary', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def _remove(self, mock_request_user_sync: Any, data1: Optional[dict] = None):
        """
        POST to remove an email address form the test user

        :param data: to control what data is POSTed to the service
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self.browser.post('/remove')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                with self.app.test_request_context():
                    data = {'csrf_token': sess.get_csrf_token()}
                    if data1 is not None:
                        data.update(data1)

                return client.post('/remove', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def _resend_code(self, mock_request_user_sync: Any, mock_sendmail: Any, data1: Optional[dict] = None):
        """
        Trigger resending a new verification code to the email being verified

        :param data: to control what data is POSTed to the service
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                with self.app.test_request_context():
                    data = {'csrf_token': sess.get_csrf_token()}
                    if data1 is not None:
                        data.update(data1)

                return client.post('/resend-code', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.email.verifications.get_unique_hash')
    def _verify(
        self,
        mock_code_verification: Any,
        mock_request_user_sync: Any,
        mock_sendmail: Any,
        data1: Optional[dict] = None,
        data2: Optional[dict] = None,
    ):
        """
        POST a new email address for the test user, and then verify it.

        :param data1: to control what data is POSTed to the /new endpoint
        :param data2: to control what data is POSTed to the /verify endpoint
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_code_verification.return_value = '432123425'
        mock_sendmail.return_value = True

        response = self.browser.post('/verify')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'email': 'john-smith3@example.com',
                        'verified': False,
                        'primary': False,
                        'csrf_token': sess.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)

                client.post('/new', data=json.dumps(data), content_type=self.content_type_json)

            with client.session_transaction() as sess:
                data = {
                    'csrf_token': sess.get_csrf_token(),
                    'email': 'john-smith3@example.com',
                    'code': '432123425',
                }
                if data2 is not None:
                    data.update(data2)

                return client.post('/verify', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.email.verifications.get_unique_hash')
    def _verify_email_link(
        self,
        mock_code_verification: Any,
        mock_request_user_sync: Any,
        mock_sendmail: Any,
        code: str = '432123425',
        data1: Optional[dict] = None,
    ):
        """
        Verify email address in the test user, using a GET to the verification endpoint

        :param code: the verification code to use
        :param data1: to control the data POSTed to the /new endpoint
        """
        mock_code_verification.return_value = '432123425'
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        email = 'johnsmith3@example.com'

        response = self.browser.post('/verify')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'csrf_token': sess.get_csrf_token(),
                        'email': email,
                        'verified': False,
                        'primary': False,
                    }
                    if data1 is not None:
                        data.update(data1)

                client.post('/new', data=json.dumps(data), content_type=self.content_type_json)

            with client.session_transaction():
                return client.get('/verify?code={}&email={}'.format(code, email))

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.email.verifications.get_unique_hash')
    def _get_code_backdoor(
        self,
        mock_code_verification: Any,
        mock_request_user_sync: Any,
        mock_sendmail: Any,
        data1: Optional[dict] = None,
        email: str = 'johnsmith3@example.com',
        code: str = '123456',
    ):
        """
        POST email data to generate a verification state,
        and try to get the generated code through the backdoor

        :param data1: to override the data POSTed by default
        :param email: email to use
        :param code: mock generated code
        """
        mock_code_verification.return_value = code
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendmail.return_value = True
        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                with self.app.test_request_context():
                    data = {
                        'email': email,
                        'verified': False,
                        'primary': False,
                        'csrf_token': sess.get_csrf_token(),
                    }
                    if data1 is not None:
                        data.update(data1)

                client.post('/new', data=json.dumps(data), content_type=self.content_type_json)

                client.set_cookie(
                    'localhost', key=self.app.config.magic_cookie_name, value=self.app.config.magic_cookie
                )

                return client.get(f'/get-code?email={email}&eppn={eppn}')

    # actual test methods

    def test_get_all_emails(self):
        email_data = self._get_all_emails()

        self.assertEqual(email_data['type'], 'GET_EMAIL_ALL_SUCCESS')
        self.assertEqual(email_data['payload']['emails'][0].get('email'), 'johnsmith@example.com')
        self.assertEqual(email_data['payload']['emails'][0].get('verified'), True)
        self.assertEqual(email_data['payload']['emails'][1].get('email'), 'johnsmith2@example.com')
        self.assertEqual(email_data['payload']['emails'][1].get('verified'), False)

    def test_post_email(self):
        response = self._post_email()

        self.assertEqual(response.status_code, 200)
        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data['type'], 'POST_EMAIL_NEW_SUCCESS')
        self.assertEqual(new_email_data['payload']['emails'][2].get('email'), 'johnsmith3@example.com')
        self.assertEqual(new_email_data['payload']['emails'][2].get('verified'), False)

    def test_post_email_try_verify(self):
        data1 = {'verified': True}
        response = self._post_email(data1=data1)

        self.assertEqual(response.status_code, 200)
        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data['type'], 'POST_EMAIL_NEW_SUCCESS')
        self.assertEqual(new_email_data['payload']['emails'][2].get('email'), 'johnsmith3@example.com')
        self.assertEqual(new_email_data['payload']['emails'][2].get('verified'), False)

    def test_post_email_try_primary(self):
        data1 = {'verified': True, 'primary': True}
        response = self._post_email(data1=data1)

        self.assertEqual(response.status_code, 200)
        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data['type'], 'POST_EMAIL_NEW_SUCCESS')
        self.assertEqual(new_email_data['payload']['emails'][2].get('email'), 'johnsmith3@example.com')
        self.assertEqual(new_email_data['payload']['emails'][2].get('verified'), False)
        self.assertEqual(new_email_data['payload']['emails'][2].get('primary'), False)

    def test_post_email_with_stale_state(self):
        # set negative throttling timeout to simulate a stale state
        self.app.config.throttle_resend_seconds = -500
        eppn = self.test_user_data['eduPersonPrincipalName']
        email = 'johnsmith3@example.com'
        verification1 = EmailProofingElement.from_dict(dict(email=email, verification_code='test_code_1'))
        modified_ts = datetime.now(tz=None)
        old_state = EmailProofingState(id=None, eppn=eppn, modified_ts=modified_ts, verification=verification1)
        self.app.proofing_statedb.save(old_state, check_sync=False)

        response = self._post_email()
        self.assertEqual(response.status_code, 200)
        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data['type'], 'POST_EMAIL_NEW_SUCCESS')
        self.assertEqual(new_email_data['payload']['emails'][2].get('email'), email)
        self.assertEqual(new_email_data['payload']['emails'][2].get('verified'), False)

    def test_post_email_throttle(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        email = 'johnsmith3@example.com'
        modified_ts = datetime.now(tz=None)
        verification1 = EmailProofingElement.from_dict(dict(email=email, verification_code='test_code_1'))
        old_state = EmailProofingState(id=None, eppn=eppn, modified_ts=modified_ts, verification=verification1)
        self.app.proofing_statedb.save(old_state, check_sync=False)

        response = self._post_email()
        self.assertEqual(response.status_code, 200)
        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data['type'], 'POST_EMAIL_NEW_SUCCESS')
        self.assertEqual(new_email_data['payload']['message'], 'emails.added-and-throttled')

    def test_post_email_error_no_data(self):
        response = self._post_email(send_data=False)

        new_email_data = json.loads(response.data)
        self.assertEqual(new_email_data['type'], 'POST_EMAIL_NEW_FAIL')

    def test_post_email_duplicate(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        email = 'johnsmith3@example.com'

        # Save unverified mail address for test user
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        mail_address = MailAddress.from_dict(dict(email=email, created_by='email', verified=False, primary=False))
        user.mail_addresses.add(mail_address)
        self.app.central_userdb.save(user, check_sync=False)

        response = self._post_email()
        self.assertEqual(response.status_code, 200)
        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data['type'], 'POST_EMAIL_NEW_FAIL')
        self.assertEqual(new_email_data['payload']['error']['email'][0], 'emails.duplicated')

    def test_post_email_bad_csrf(self):
        response = self._post_email(data1={'csrf_token': 'bad-token'})

        self.assertEqual(response.status_code, 200)

        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data['type'], 'POST_EMAIL_NEW_FAIL')
        self.assertEqual(new_email_data['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_post_primary(self, mock_request_user_sync):
        data1 = {'email': 'johnsmith@example.com'}
        response = self._post_primary(data1=data1)

        self.assertEqual(response.status_code, 200)

        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data['type'], 'POST_EMAIL_PRIMARY_SUCCESS')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_post_unknown_primary(self, mock_request_user_sync):
        data1 = {'email': 'susansmith@example.com'}
        response = self._post_primary(data1=data1)

        self.assertEqual(response.status_code, 200)

        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data['type'], 'POST_EMAIL_PRIMARY_FAIL')

    def test_post_primary_missing(self):
        data1 = {'email': 'johnsmith3@example.com'}
        response = self._post_primary(data1=data1)

        self.assertEqual(response.status_code, 200)

        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data['type'], 'POST_EMAIL_PRIMARY_FAIL')
        self.assertEqual(new_email_data['payload']['error']['email'][0], 'emails.missing')

    def test_post_primary_unconfirmed_fail(self):
        data1 = {'email': 'johnsmith2@example.com'}
        response = self._post_primary(data1=data1)

        self.assertEqual(response.status_code, 200)

        new_email_data = json.loads(response.data)

        self.assertEqual(new_email_data['type'], 'POST_EMAIL_PRIMARY_FAIL')
        self.assertEqual(new_email_data['payload']['message'], 'emails.unconfirmed_address_not_primary')

    def test_remove(self):
        data1 = {'email': 'johnsmith2@example.com'}
        response = self._remove(data1=data1)

        self.assertEqual(response.status_code, 200)

        delete_email_data = json.loads(response.data)

        self.assertEqual(delete_email_data['type'], 'POST_EMAIL_REMOVE_SUCCESS')
        self.assertEqual(delete_email_data['payload']['emails'][0].get('email'), 'johnsmith@example.com')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_remove_primary(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data['eduPersonPrincipalName']
        user = self.app.central_userdb.get_user_by_eppn(eppn)

        # Remove all mail addresses to start with a known state
        self._remove_all_emails(user)

        # Add one verified, primary address and one not verified
        self._add_2_emails(user)

        self.request_user_sync(user)

        data1 = {'email': 'verified@example.com'}
        response = self._remove(data1=data1)

        self.assertEqual(response.status_code, 200)
        delete_email_data = json.loads(response.data)
        self.assertEqual(delete_email_data['type'], 'POST_EMAIL_REMOVE_SUCCESS')
        self.assertEqual(delete_email_data['payload']['emails'][0].get('email'), 'verified2@example.com')

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        self.assertEqual(user.mail_addresses.count, 1)
        self.assertEqual(user.mail_addresses.verified.count, 1)
        self.assertEqual(user.mail_addresses.primary.email, 'verified2@example.com')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_remove_last_verified(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data['eduPersonPrincipalName']
        user = self.app.central_userdb.get_user_by_eppn(eppn)

        # Remove all mail addresses to start with a known state
        self._remove_all_emails(user)

        # Add one verified, primary address and one not verified
        self._add_2_emails_1_verified(user)

        self.request_user_sync(user)

        data1 = {'email': 'verified@example.com'}
        response = self._remove(data1=data1)

        self.assertEqual(response.status_code, 200)
        delete_email_data = json.loads(response.data)
        self.assertEqual(delete_email_data['type'], 'POST_EMAIL_REMOVE_FAIL')

        user = self.app.central_userdb.get_user_by_eppn(eppn)
        self.assertEqual(user.mail_addresses.count, 2)
        self.assertEqual(user.mail_addresses.verified.count, 1)
        self.assertEqual(user.mail_addresses.primary.email, 'verified@example.com')

    def test_remove_fail(self):
        data1 = {'email': 'johnsmith3@example.com'}
        response = self._remove(data1=data1)

        self.assertEqual(response.status_code, 200)
        delete_email_data = json.loads(response.data)

        self.assertEqual(delete_email_data['type'], 'POST_EMAIL_REMOVE_FAIL')
        self.assertEqual(delete_email_data['payload']['error']['email'][0], 'emails.missing')

    def test_resend_code(self):
        response = self.browser.post('/resend-code')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        data1 = {'email': 'johnsmith@example.com'}
        response = self._resend_code(data1=data1)

        self.assertEqual(response.status_code, 200)
        resend_code_email_data = json.loads(response.data)

        self.assertEqual(resend_code_email_data['type'], 'POST_EMAIL_RESEND_CODE_SUCCESS')
        self.assertEqual(resend_code_email_data['payload']['emails'][0].get('email'), 'johnsmith@example.com')
        self.assertEqual(resend_code_email_data['payload']['emails'][1].get('email'), 'johnsmith2@example.com')

    def test_throttle_resend_code(self):
        data1 = {'email': 'johnsmith@example.com'}
        response = self._resend_code(data1=data1)

        self.assertEqual(response.status_code, 200)

        response2 = self._resend_code(data1=data1)

        self.assertEqual(response2.status_code, 200)

        resend_code_email_data = json.loads(response2.data)

        self.assertEqual(resend_code_email_data['type'], 'POST_EMAIL_RESEND_CODE_FAIL')
        self.assertEqual(resend_code_email_data['error'], True)
        self.assertEqual(resend_code_email_data['payload']['message'], 'still-valid-code')
        self.assertIsNotNone(resend_code_email_data['payload']['csrf_token'])

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_resend_code_fails(self, mock_request_user_sync):
        data1 = {'email': 'johnsmith3@example.com'}
        response = self._resend_code(data1=data1)

        self.assertEqual(response.status_code, 200)
        resend_code_email_data = json.loads(response.data)

        self.assertEqual(resend_code_email_data['type'], 'POST_EMAIL_RESEND_CODE_FAIL')

        self.assertEqual(resend_code_email_data['payload']['error']['email'][0], 'emails.missing')

    def test_verify(self):
        response = self._verify()

        verify_email_data = json.loads(response.data)
        self.assertEqual(verify_email_data['type'], 'POST_EMAIL_VERIFY_SUCCESS')
        self.assertEqual(verify_email_data['payload']['emails'][2]['email'], 'john-smith3@example.com')
        self.assertEqual(verify_email_data['payload']['emails'][2]['verified'], True)
        self.assertEqual(verify_email_data['payload']['emails'][2]['primary'], False)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    def test_verify_unknown(self):
        data2 = {'email': 'susan@example.com'}
        response = self._verify(data2=data2)

        verify_email_data = json.loads(response.data)
        self.assertEqual(verify_email_data['type'], 'POST_EMAIL_VERIFY_FAIL')

    def test_verify_no_primary(self):
        # Remove all mail addresses to start with no primary address
        eppn = self.test_user_data['eduPersonPrincipalName']
        user = self.app.private_userdb.get_user_by_eppn(eppn)
        self._remove_all_emails(user)
        self.request_user_sync(user)

        response = self._verify()

        verify_email_data = json.loads(response.data)
        self.assertEqual(verify_email_data['type'], 'POST_EMAIL_VERIFY_SUCCESS')
        self.assertEqual(len(verify_email_data['payload']['emails']), 1)
        self.assertEqual(verify_email_data['payload']['emails'][0]['email'], 'john-smith3@example.com')
        self.assertEqual(verify_email_data['payload']['emails'][0]['verified'], True)
        self.assertEqual(verify_email_data['payload']['emails'][0]['primary'], True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.email.verifications.get_unique_hash')
    def test_verify_code_timeout(self, mock_code_verification, mock_request_user_sync, mock_sendmail):
        self.app.config.email_verification_timeout = 0
        response = self._verify()

        verify_email_data = json.loads(response.data)
        self.assertEqual(verify_email_data['type'], 'POST_EMAIL_VERIFY_FAIL')
        self.assertEqual(verify_email_data['payload']['message'], 'emails.code_invalid_or_expired')

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.email.verifications.get_unique_hash')
    def test_verify_fail(self, mock_code_verification, mock_request_user_sync, mock_sendmail):
        response = self._verify(data2={'code': 'wrong-code'})

        verify_email_data = json.loads(response.data)
        self.assertEqual(verify_email_data['type'], 'POST_EMAIL_VERIFY_FAIL')
        self.assertEqual(verify_email_data['payload']['message'], 'emails.code_invalid_or_expired')
        self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.email.verifications.get_unique_hash')
    def test_verify_email_link(self, mock_code_verification, mock_request_user_sync, mock_sendmail):
        response = self._verify_email_link()
        email = 'johnsmith3@example.com'
        eppn = self.test_user_data['eduPersonPrincipalName']

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, 'http://test.localhost/profile/?msg=emails.verification-success')

        user = self.app.private_userdb.get_user_by_eppn(eppn)
        mail_address_element = user.mail_addresses.find(email)
        self.assertTrue(mail_address_element)

        self.assertEqual(mail_address_element.email, email)
        self.assertEqual(mail_address_element.is_verified, True)
        self.assertEqual(mail_address_element.is_primary, False)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.email.verifications.get_unique_hash')
    def test_verify_email_link_wrong_code(self, mock_code_verification, mock_request_user_sync, mock_sendmail):
        response = self._verify_email_link(code='wrong-code')
        email = 'johnsmith3@example.com'
        eppn = self.test_user_data['eduPersonPrincipalName']
        user = self.app.private_userdb.get_user_by_eppn(eppn)
        mail_address_element = user.mail_addresses.find(email)
        self.assertTrue(mail_address_element)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.location, 'http://test.localhost/profile/?msg=%3AERROR%3Aemails.code_invalid_or_expired'
        )

        user = self.app.private_userdb.get_user_by_eppn(eppn)
        mail_address_element = user.mail_addresses.find(email)
        self.assertTrue(mail_address_element)

        self.assertEqual(mail_address_element.email, email)
        self.assertEqual(mail_address_element.is_verified, False)
        self.assertEqual(mail_address_element.is_primary, False)
        self.assertEqual(self.app.proofing_log.db_count(), 0)

    def test_handle_multiple_email_proofings(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        email = 'example@example.com'
        verification1 = EmailProofingElement.from_dict(dict(email=email, verification_code='test_code_1'))
        verification2 = EmailProofingElement.from_dict(dict(email=email, verification_code='test_code_2'))
        modified_ts = datetime.now(tz=None) - timedelta(seconds=1)
        state1 = EmailProofingState(id=None, eppn=eppn, modified_ts=modified_ts, verification=verification1)
        state2 = EmailProofingState(id=None, eppn=eppn, modified_ts=None, verification=verification2)
        self.app.proofing_statedb.save(state1, check_sync=False)
        self.app.proofing_statedb.save(state2, check_sync=False)
        state = self.app.proofing_statedb.get_state_by_eppn_and_email(eppn=eppn, email=email)
        self.assertEqual(state.verification.verification_code, 'test_code_2')

    def test_get_code_backdoor(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'dev'

        code = '0123456'
        resp = self._get_code_backdoor(code=code)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data, code.encode('ascii'))

    def test_get_code_no_backdoor_in_pro(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'pro'

        code = '0123456'
        resp = self._get_code_backdoor(code=code)

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured1(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = ''
        self.app.config.environment = 'dev'

        code = '0123456'
        resp = self._get_code_backdoor(code=code)

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured2(self):
        self.app.config.magic_cookie = ''
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'dev'

        code = '0123456'
        resp = self._get_code_backdoor(code=code)

        self.assertEqual(resp.status_code, 400)
