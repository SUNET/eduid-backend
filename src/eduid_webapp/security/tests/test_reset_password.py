# -*- coding: utf-8 -*-
from __future__ import absolute_import

from mock import patch
from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.security.app import security_init_app

__author__ = 'lundberg'


class SecurityResetPasswordTests(EduidAPITestCase):

    def setUp(self, create_user=True):
        self.test_user_eppn = 'hubba-bubba'
        super(SecurityResetPasswordTests, self).setUp()

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return security_init_app('testing', config)

    def update_config(self, config):
        config.update({
            'AVAILABLE_LANGUAGES': {'en': 'English', 'sv': 'Svenska'},
            'MSG_BROKER_URL': 'amqp://dummy',
            'AM_BROKER_URL': 'amqp://dummy',
            'CELERY_CONFIG': {
                'CELERY_RESULT_BACKEND': 'amqp',
                'CELERY_TASK_SERIALIZER': 'json'
            },
            'EMAIL_CODE_TIMEOUT_MINUTES': 120,
            'PHONE_CODE_TIMEOUT_MINUTES': 10
        })
        return config

    def tearDown(self):
        super(SecurityResetPasswordTests, self).tearDown()
        with self.app.app_context():
            self.app.private_userdb._drop_whole_collection()
            self.app.authninfo_db._drop_whole_collection()
            self.app.password_reset_state_db._drop_whole_collection()
            self.app.proofing_log._drop_whole_collection()
            self.app.central_userdb._drop_whole_collection()

    def post_email_address(self, email_address):
        with self.app.test_client() as c:
            c.get('/reset-password/')
            with c.session_transaction() as sess:
                data = {
                    'csrf': sess.get_csrf_token(),
                    'email': email_address
                }
            response2 = c.post('/reset-password/', data=data)
            self.assertEqual(response2.status_code, 200)

    def verify_email_address(self, email_code):
        with self.app.test_client() as c:
            response2 = c.get('/reset-password/email/{}'.format(email_code))

            self.assertEqual(response2.status_code, 302)
            self.assertEqual(response2.location, 'http://{}/reset-password/extra-security/{}'.format(
                             self.app.config['SERVER_NAME'], email_code))

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
        email_code = state.email_code.code

        self.verify_email_address(email_code)

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)
        self.assertEqual(state.email_code.verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    def test_password_reset_extra_security_no_verified_email(self, mock_sendmail):
        mock_sendmail.return_value = True
        self.post_email_address('johnsmith@example.com')

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)
        email_code = state.email_code.code

        with self.app.test_client() as c:
            response2 = c.get('/reset-password/extra-security/{}'.format(email_code))
            self.assertEqual(response2.status_code, 200)
            self.assertIn('Email address not validated', response2.data)

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)
        self.assertEqual(state.email_code.verified, False)
        self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_common.api.msg.MsgRelay.sendsms')
    def test_password_reset_extra_security_phone(self, mock_sendmail, mock_sendsms):
        mock_sendmail.return_value = True
        mock_sendsms.return_value = True
        self.post_email_address('johnsmith@example.com')

        state = self.app.password_reset_state_db.get_state_by_eppn(self.test_user_eppn)
        self.assertIsNotNone(state)
        email_code = state.email_code.code

        self.verify_email_address(email_code)

        with self.app.test_client() as c:
            c.get('/reset-password/extra-security/{}'.format(email_code))
            with c.session_transaction() as sess:
                data = {
                    'csrf': sess.get_csrf_token(),
                    'phone_number_index': '0'
                }
            response2 = c.post('/reset-password/extra-security/{}'.format(email_code), data=data)
            self.assertEqual(response2.status_code, 302)

            response3 = c.get('/reset-password/extra-security/phone/{}'.format(email_code))
            self.assertEqual(response3.status_code, 200)

            with c.session_transaction() as sess:
                data = {
                    'csrf': sess.get_csrf_token(),
                    'phone_number_index': '0'
                }
            response2 = c.post('/reset-password/extra-security/{}'.format(email_code), data=data)
