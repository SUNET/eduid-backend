# -*- coding: utf-8 -*-
from __future__ import absolute_import

import datetime

from eduid_common.api.exceptions import MsgTaskFailed, MailTaskFailed
from mock import patch
from eduid_common.api.testing import EduidAPITestCase
from eduid_common.authn.testing import TestVCCSClient
from eduid_userdb.credentials import Password
from eduid_userdb.exceptions import DocumentDoesNotExist
from eduid_userdb.security import PasswordResetEmailState
from eduid_webapp.security.app import security_init_app
from eduid_webapp.security.settings.common import SecurityConfig

__author__ = 'lundberg'


class SecurityResetPasswordTests(EduidAPITestCase):

    def setUp(self):
        self.test_user_eppn = 'hubba-bubba'
        super(SecurityResetPasswordTests, self).setUp()

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return security_init_app('testing', config)

    def update_config(self, app_config):
        app_config.update({
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
            'password_entropy': 25
        })
        return SecurityConfig(**app_config)

    def post_email_address(self, email_address):
        with self.app.test_client() as c:
            c.get('/reset-password/')
            with c.session_transaction() as sess:
                data = {
                    'csrf': sess.get_csrf_token(),
                    'email': email_address
                }
            response = c.post('/reset-password/', data=data)
            self.assertEqual(response.status_code, 200)
        return response

    def verify_email_address(self, state):
        with self.app.test_client() as c:
            response = c.get('/reset-password/email/{}'.format(state.email_code.code))

            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, 'http://{}/reset-password/extra-security/{}'.format(
                             self.app.config.server_name, state.email_code.code))
            self.assertEqual(self.app.proofing_log.db_count(), 1)

    def choose_extra_security_phone_number(self, state):
        with self.app.test_client() as c:
            c.get('/reset-password/extra-security/{}'.format(state.email_code.code))
            with c.session_transaction() as sess:
                data = {
                    'csrf': sess.get_csrf_token(),
                    'phone_number_index': '0'
                }
            response = c.post('/reset-password/extra-security/{}'.format(state.email_code.code), data=data)
            self.assertEqual(response.status_code, 302)

    def choose_no_extra_security(self, state):
        with self.app.test_client() as c:
            c.get('/reset-password/extra-security/{}'.format(state.email_code.code))
            with c.session_transaction() as sess:
                data = {
                    'csrf': sess.get_csrf_token(),
                    'no_extra_security': 'true'
                }
            response = c.post('/reset-password/extra-security/{}'.format(state.email_code.code), data=data)
            self.assertEqual(response.status_code, 302)

    def no_extra_security_alternatives(self, state):
        with self.app.test_client() as c:
            response = c.get('/reset-password/extra-security/{}'.format(state.email_code.code))
            self.assertEqual(response.status_code, 302)

    def verify_phone_number(self, state):
        with self.app.test_client() as c:
            c.get('/reset-password/extra-security/phone/{}'.format(state.email_code.code))

            with c.session_transaction() as sess:
                data = {
                    'csrf': sess.get_csrf_token(),
                    'phone_code': state.phone_code.code
                }
            response = c.post('/reset-password/extra-security/phone/{}'.format(state.email_code.code), data=data)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(self.app.proofing_log.db_count(), 2)

    def choose_generated_password(self, state):
        with self.app.test_client() as c:
            c.get('/reset-password/new-password/{}'.format(state.email_code.code))
            with c.session_transaction() as sess:
                data = {
                    'csrf': sess.get_csrf_token(),
                    'use_generated_password': 'true'
                }
            response = c.post('/reset-password/new-password/{}'.format(state.email_code.code), data=data)
            self.assertEqual(response.status_code, 200)

        with self.assertRaises(DocumentDoesNotExist):
            self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)

    def choose_custom_password(self, state):
        with self.app.test_client() as c:
            c.get('/reset-password/new-password/{}'.format(state.email_code.code))
            with c.session_transaction() as sess:
                data = {
                    'csrf': sess.get_csrf_token(),
                    'custom_password': 'a_pretty_long_password',
                    'repeat_password': 'a_pretty_long_password'
                }
            response = c.post('/reset-password/new-password/{}'.format(state.email_code.code), data=data)
            self.assertEqual(response.status_code, 200)

        with self.assertRaises(DocumentDoesNotExist):
            self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)

    def test_password_reset_start(self):
        response = self.browser.get('/reset-password/')
        self.assertEqual(response.status_code, 200)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_password_reset_email(self, mock_sendmail):
        mock_sendmail.return_value = True
        self.post_email_address('johnsmith@example.com')

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_password_reset_email_unknown_mail_address(self, mock_sendmail):
        mock_sendmail.return_value = True
        self.post_email_address('no_such_address@example.com')

        self.assertEqual(self.app.password_reset_state_db.db_count(), 0)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_password_reset_email_overwrite_state(self, mock_sendmail):
        mock_sendmail.return_value = True

        # Password reset 1
        self.post_email_address('johnsmith@example.com')
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)
        code1 = state.email_code.code

        # Password reset 2
        self.post_email_address('johnsmith@example.com')
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)
        code2 = state.email_code.code

        self.assertNotEqual(code1, code2)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_password_reset_email_code(self, mock_sendmail):
        mock_sendmail.return_value = True
        self.post_email_address('johnsmith@example.com')

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)

        self.verify_email_address(state)

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)
        self.assertEqual(state.email_code.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_password_reset_email_code_mail_relay_problem(self, mock_sendmail):
        mock_sendmail.side_effect = MailTaskFailed('test')
        response = self.post_email_address('johnsmith@example.com')
        self.assertIn(b'Temporary technical problem', response.data)

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)

        self.assertEqual(state.email_code.is_verified, False)
        self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_password_reset_extra_security_no_verified_email(self, mock_sendmail):
        mock_sendmail.return_value = True
        self.post_email_address('johnsmith@example.com')

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)
        email_code = state.email_code.code

        with self.app.test_client() as c:
            response = c.get('/reset-password/extra-security/{}'.format(email_code))
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Email address not validated', response.data)

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)
        self.assertEqual(state.email_code.is_verified, False)
        self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def test_password_reset_extra_security_phone(self, mock_sendmail, mock_sendsms):
        mock_sendmail.return_value = True
        mock_sendsms.return_value = True
        self.post_email_address('johnsmith@example.com')

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)

        self.verify_email_address(state)

        # Choose extra security phone and send sms
        self.choose_extra_security_phone_number(state)

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state.phone_code)
        self.assertEqual(state.phone_code.is_verified, False)

        # Verify phone
        self.verify_phone_number(state)

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertEqual(state.phone_code.is_verified, True)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def test_password_reset_extra_security_phone_msg_relay_problem(self, mock_sendsms, mock_sendmail):
        mock_sendmail.return_value = True
        mock_sendsms.side_effect = MsgTaskFailed('test')
        self.post_email_address('johnsmith@example.com')

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)

        self.verify_email_address(state)

        # Choose extra security phone and send sms
        with self.app.test_client() as c:
            c.get('/reset-password/extra-security/{}'.format(state.email_code.code))
            with c.session_transaction() as sess:
                data = {
                    'csrf': sess.get_csrf_token(),
                    'phone_number_index': '0'
                }
            response = c.post('/reset-password/extra-security/{}'.format(state.email_code.code), data=data)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Temporary technical problem', response.data)

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state.phone_code)
        self.assertEqual(state.phone_code.is_verified, False)

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_reset_password_with_extra_security_phone(self, mock_request_user_sync, mock_sendsms, mock_sendmail,
                                                      mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendsms.return_value = True
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        old_passwords = user.credentials.filter(Password).to_list()

        self.post_email_address('johnsmith@example.com')
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.verify_email_address(state)
        self.choose_extra_security_phone_number(state)
        state = self.app.password_reset_state_db.get_state_by_email_code(state.email_code.code)
        self.verify_phone_number(state)
        self.choose_generated_password(state)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.credentials.filter(Password).count, 1)
        self.assertNotEqual(user.credentials.filter(Password).to_list(), old_passwords)
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(user.phone_numbers.primary.is_verified, True)

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_reset_password_with_extra_security_phone_expired(self, mock_request_user_sync, mock_sendsms,
                                                              mock_sendmail, mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendsms.return_value = True
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()

        self.post_email_address('johnsmith@example.com')
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.verify_email_address(state)
        self.choose_extra_security_phone_number(state)
        state = self.app.password_reset_state_db.get_state_by_email_code(state.email_code.code)
        self.app.logger.info('Moving phone-expire-state back in time')
        # Move state back in time so that the code will be expired
        state.phone_code._data['created_ts'] = None
        state.phone_code.created_ts = datetime.datetime.fromtimestamp(123)
        self.app.password_reset_state_db.save(state)
        self.app.logger.info(f'Saved expired state: {state}')

        with self.app.test_client() as c:
            resp = c.get('/reset-password/extra-security/phone/{}'.format(state.email_code.code))
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b'The phone verification has expired.', resp.data)

        state = self.app.password_reset_state_db.get_state_by_email_code(state.email_code.code)
        # check that state has been 'downgraded' to email again
        self.assertIsInstance(state, PasswordResetEmailState)

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_reset_password_with_no_extra_security(self, mock_request_user_sync, mock_sendsms, mock_sendmail,
                                                   mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendsms.return_value = True
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        old_passwords = user.credentials.filter(Password).to_list()

        self.post_email_address('johnsmith@example.com')
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.verify_email_address(state)
        self.choose_no_extra_security(state)
        self.choose_generated_password(state)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.credentials.filter(Password).count, 1)
        self.assertNotEqual(user.credentials.filter(Password).to_list(), old_passwords)
        for nin in user.nins.to_list():
            self.assertEqual(nin.is_verified, False)
        for phone_number in user.phone_numbers.to_list():
            self.assertEqual(phone_number.is_verified, False)

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_reset_password_with_no_extra_security_available(self, mock_request_user_sync, mock_sendsms, mock_sendmail,
                                                             mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendsms.return_value = True
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()

        # Remove extra security alternatives
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        for phone in user.phone_numbers.verified.to_list():
            user.phone_numbers.remove(phone.number)
        self.request_user_sync(user)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        old_passwords = user.credentials.filter(Password).to_list()

        self.post_email_address('johnsmith@example.com')
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.verify_email_address(state)
        self.no_extra_security_alternatives(state)
        self.choose_generated_password(state)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.credentials.filter(Password).count, 1)
        self.assertNotEqual(user.credentials.filter(Password).to_list(), old_passwords)
        for nin in user.nins.to_list():
            self.assertEqual(nin.is_verified, False)
        for phone_number in user.phone_numbers.to_list():
            self.assertEqual(phone_number.is_verified, False)

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_reset_custom_password_with_extra_security_phone(self, mock_request_user_sync, mock_sendsms, mock_sendmail,
                                                             mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendsms.return_value = True
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        old_passwords = user.credentials.filter(Password).to_list()

        self.post_email_address('johnsmith@example.com')
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.verify_email_address(state)
        self.choose_extra_security_phone_number(state)
        state = self.app.password_reset_state_db.get_state_by_email_code(state.email_code.code)
        self.verify_phone_number(state)
        self.choose_custom_password(state)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.credentials.filter(Password).count, 1)
        self.assertNotEqual(user.credentials.filter(Password).to_list(), old_passwords)
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(user.phone_numbers.primary.is_verified, True)

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_reset_custom_password_with_no_extra_security(self, mock_request_user_sync, mock_sendsms, mock_sendmail,
                                                          mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendsms.return_value = True
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        old_password = user.credentials.filter(Password).to_list()[0]

        self.post_email_address('johnsmith@example.com')
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.verify_email_address(state)
        self.choose_no_extra_security(state)
        self.choose_custom_password(state)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.credentials.filter(Password).count, 1)
        self.assertNotEqual(user.credentials.filter(Password).to_list()[0].key, old_password.key)
        for nin in user.nins.to_list():
            self.assertEqual(nin.is_verified, False)
        for phone_number in user.phone_numbers.to_list():
            self.assertEqual(phone_number.is_verified, False)

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_reset_password_low_entropy(self, mock_request_user_sync, mock_sendsms, mock_sendmail,
                                        mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendsms.return_value = True
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        old_password = user.credentials.filter(Password).to_list()[0]

        self.post_email_address('johnsmith@example.com')
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.verify_email_address(state)
        self.choose_no_extra_security(state)

        with self.app.test_client() as c:
            c.get('/reset-password/new-password/{}'.format(state.email_code.code))
            with c.session_transaction() as sess:
                data = {
                    'csrf': sess.get_csrf_token(),
                    'custom_password': 'bad',
                    'repeat_password': 'bad'
                }
            response = c.post('/reset-password/new-password/{}'.format(state.email_code.code), data=data)
            self.assertEqual(response.status_code, 200)

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)

        # Check that nothing changed
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.credentials.filter(Password).count, 1)
        self.assertEqual(user.credentials.filter(Password).to_list()[0].key, old_password.key)
        for nin in user.nins.verified.to_list():
            self.assertEqual(nin.is_verified, True)
        for phone_number in user.phone_numbers.verified.to_list():
            self.assertEqual(phone_number.is_verified, True)

    @patch('eduid_common.authn.vccs.get_vccs_client')
    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_reset_password_blank_password(self, mock_request_user_sync, mock_sendsms, mock_sendmail,
                                           mock_get_vccs_client):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_sendsms.return_value = True
        mock_sendmail.return_value = True
        mock_get_vccs_client.return_value = TestVCCSClient()

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        old_password = user.credentials.filter(Password).to_list()[0]

        self.post_email_address('johnsmith@example.com')
        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.verify_email_address(state)
        self.choose_no_extra_security(state)

        with self.app.test_client() as c:
            c.get('/reset-password/new-password/{}'.format(state.email_code.code))
            with c.session_transaction() as sess:
                data = {
                    'csrf': sess.get_csrf_token(),
                    'custom_password': '',
                    'repeat_password': ''
                }
            response = c.post('/reset-password/new-password/{}'.format(state.email_code.code), data=data)
            self.assertEqual(response.status_code, 200)

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)

        # Check that nothing changed
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.credentials.filter(Password).count, 1)
        self.assertEqual(user.credentials.filter(Password).to_list()[0].key, old_password.key)
        for nin in user.nins.verified.to_list():
            self.assertEqual(nin.is_verified, True)
        for phone_number in user.phone_numbers.verified.to_list():
            self.assertEqual(phone_number.is_verified, True)
