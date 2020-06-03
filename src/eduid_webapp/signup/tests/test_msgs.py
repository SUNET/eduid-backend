# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.signup.helpers import SignupMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(SignupMsg.no_tou.value, 'signup.tou-not-accepted')
        self.assertEqual(SignupMsg.reg_new.value, 'signup.registering-new')
        self.assertEqual(SignupMsg.email_used.value, 'signup.registering-address-used')
        self.assertEqual(SignupMsg.no_recaptcha.value, 'signup.recaptcha-not-verified')
        self.assertEqual(SignupMsg.resent_success.value, 'signup.verification-present')
        self.assertEqual(SignupMsg.unknown_code.value, 'signup.unknown-code')
        self.assertEqual(SignupMsg.already_verified.value, 'signup.already-verified')
