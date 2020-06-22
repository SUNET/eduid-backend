# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.reset_password.helpers import ResetPwMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(ResetPwMsg.unknown_code.value, 'resetpw.unknown-code')
        self.assertEqual(ResetPwMsg.unknown_phone_code.value, 'resetpw.phone-code-unknown')
        self.assertEqual(ResetPwMsg.expired_email_code.value, 'resetpw.expired-email-code')
        self.assertEqual(ResetPwMsg.expired_sms_code.value, 'resetpw.expired-sms-code')
        self.assertEqual(ResetPwMsg.send_pw_failure.value, 'resetpw.send-pw-fail')
        self.assertEqual(ResetPwMsg.send_pw_success.value, 'resetpw.send-pw-success')
        self.assertEqual(ResetPwMsg.pw_resetted.value, 'resetpw.pw-resetted')
        self.assertEqual(ResetPwMsg.send_sms_throttled.value, 'resetpw.sms-throttled')
        self.assertEqual(ResetPwMsg.send_sms_failure.value, 'resetpw.sms-failed')
        self.assertEqual(ResetPwMsg.send_sms_success.value, 'resetpw.sms-success')
        self.assertEqual(ResetPwMsg.phone_invalid.value, 'resetpw.phone-invalid')
        self.assertEqual(ResetPwMsg.user_not_found.value, 'resetpw.user-not-found')
        self.assertEqual(ResetPwMsg.email_not_validated.value, 'resetpw.email-not-validated')
        self.assertEqual(ResetPwMsg.invalid_user.value, 'resetpw.incomplete-user')
        self.assertEqual(ResetPwMsg.no_reauthn.value, 'chpass.no_reauthn')
        self.assertEqual(ResetPwMsg.stale_reauthn.value, 'chpass.stale_reauthn')
        self.assertEqual(ResetPwMsg.unrecognized_pw.value, 'chpass.unable-to-verify-old-password')
        self.assertEqual(ResetPwMsg.hwtoken_fail.value, 'security-key-fail')
        self.assertEqual(ResetPwMsg.state_no_key.value, 'chpass.no-code-in-data')
        self.assertEqual(ResetPwMsg.chpass_weak.value, 'chpass.weak-password')
        self.assertEqual(ResetPwMsg.chpass_no_data.value, 'chpass.no-data')
        self.assertEqual(ResetPwMsg.mfa_no_data.value, 'mfa.no-request-data')
        self.assertEqual(ResetPwMsg.fido_token_fail.value, 'resetpw.fido-token-fail')
        self.assertEqual(ResetPwMsg.resetpw_weak.value, 'resetpw.weak-password')
        self.assertEqual(ResetPwMsg.invalid_email.value, 'Invalid email address')
        self.assertEqual(ResetPwMsg.chpass_password_changed.value, 'chpass.password-changed')
