# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.signup.helpers import SignupMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(str(SignupMsg.out_of_sync.value), 'user-out-of-sync')
        self.assertEqual(str(SignupMsg.temp_problem.value), 'Temporary technical problems')
        self.assertEqual(str(SignupMsg.no_tou.value), 'signup.tou-not-accepted')
        self.assertEqual(str(SignupMsg.reg_new.value), 'signup.registering-new')
        self.assertEqual(str(SignupMsg.email_used.value), 'signup.registering-address-used')
        self.assertEqual(str(SignupMsg.no_recaptcha.value), 'signup.recaptcha-not-verified')
        self.assertEqual(str(SignupMsg.resent_success.value), 'signup.verification-present')
        self.assertEqual(str(SignupMsg.unknown_code.value), 'signup.unknown-code')
        self.assertEqual(str(SignupMsg.already_verified.value), 'signup.already-verified')
