# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.reset_password.helpers import ResetPwMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(ResetPwMsg.state_not_found.value, 'resetpw.state-not-found')
        self.assertEqual(ResetPwMsg.unknown_phone_code.value, 'resetpw.phone-code-unknown')
        self.assertEqual(ResetPwMsg.expired_email_code.value, 'resetpw.expired-email-code')
        self.assertEqual(ResetPwMsg.expired_phone_code.value, 'resetpw.expired-phone-code')
        self.assertEqual(ResetPwMsg.reset_pw_initialized.value, 'resetpw.reset-pw-initialized')
        self.assertEqual(ResetPwMsg.pw_reset_success.value, 'resetpw.pw-reset-success')
        self.assertEqual(ResetPwMsg.send_sms_throttled.value, 'resetpw.sms-throttled')
        self.assertEqual(ResetPwMsg.send_sms_failure.value, 'resetpw.sms-failed')
        self.assertEqual(ResetPwMsg.send_sms_success.value, 'resetpw.sms-success')
        self.assertEqual(ResetPwMsg.phone_invalid.value, 'resetpw.phone-invalid')
        self.assertEqual(ResetPwMsg.user_not_found.value, 'resetpw.user-not-found')
        self.assertEqual(ResetPwMsg.email_not_validated.value, 'resetpw.email-not-validated')
        self.assertEqual(ResetPwMsg.invalid_user.value, 'resetpw.incomplete-user')
        self.assertEqual(ResetPwMsg.fido_token_fail.value, 'resetpw.fido-token-fail')
        self.assertEqual(ResetPwMsg.resetpw_weak.value, 'resetpw.weak-password')
