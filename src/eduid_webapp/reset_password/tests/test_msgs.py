# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.reset_password.helpers import ResetPwMsg


class MessagesTests(unittest.TestCase):

    def test_messages(self):
        """"""
        self.assertEqual(str(ResetPwMsg.unknown_code.value), 'resetpw.unknown-code')
        self.assertEqual(str(ResetPwMsg.unkown_phone_code.value), 'resetpw.phone-code-unknown')
        self.assertEqual(str(ResetPwMsg.expired_email_code.value), 'resetpw.expired-email-code')
        self.assertEqual(str(ResetPwMsg.expired_sms_code.value), 'resetpw.expired-sms-code')
        self.assertEqual(str(ResetPwMsg.send_pw_failure.value), 'resetpw.send-pw-fail')
        self.assertEqual(str(ResetPwMsg.send_pw_success.value), 'resetpw.send-pw-success')
        self.assertEqual(str(ResetPwMsg.pw_resetted.value), 'resetpw.pw-resetted')
        self.assertEqual(str(ResetPwMsg.send_sms_throttled.value), 'resetpw.sms-throttled')
        self.assertEqual(str(ResetPwMsg.send_sms_failure.value), 'resetpw.sms-failed')
        self.assertEqual(str(ResetPwMsg.send_sms_success.value), 'resetpw.sms-success')
        self.assertEqual(str(ResetPwMsg.phone_invalid.value), 'resetpw.phone-invalid')
        self.assertEqual(str(ResetPwMsg.user_not_found.value), 'resetpw.user-not-found')
        self.assertEqual(str(ResetPwMsg.email_not_validated.value), 'resetpw.email-not-validated')
        self.assertEqual(str(ResetPwMsg.invalid_user.value), 'resetpw.incomplete-user')
        self.assertEqual(str(ResetPwMsg.no_reauthn.value), 'chpass.no_reauthn')
        self.assertEqual(str(ResetPwMsg.stale_reauthn.value), 'chpass.stale_reauthn')
        self.assertEqual(str(ResetPwMsg.unrecognized_pw.value), 'chpass.unable-to-verify-old-password')
        self.assertEqual(str(ResetPwMsg.out_of_sync.value), 'user-out-of-sync')
        self.assertEqual(str(ResetPwMsg.hwtoken_fail.value), 'security-key-fail')
        self.assertEqual(str(ResetPwMsg.state_no_key.value), 'chpass.no-code-in-data')
        self.assertEqual(str(ResetPwMsg.csrf_try_again.value), 'csrf.try_again')
        self.assertEqual(str(ResetPwMsg.csrf_missing.value), 'csrf.missing')
        self.assertEqual(str(ResetPwMsg.chpass_weak.value), 'chpass.weak-password')
        self.assertEqual(str(ResetPwMsg.chpass_no_data.value), 'chpass.no-data')
        self.assertEqual(str(ResetPwMsg.mfa_no_data.value), 'mfa.no-request-data')
        self.assertEqual(str(ResetPwMsg.fido_token_fail.value), 'resetpw.fido-token-fail')
        self.assertEqual(str(ResetPwMsg.resetpw_weak.value), 'resetpw.weak-password')
        self.assertEqual(str(ResetPwMsg.invalid_email.value), 'Invalid email address')
