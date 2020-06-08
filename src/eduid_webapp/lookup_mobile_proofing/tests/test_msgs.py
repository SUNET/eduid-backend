# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.lookup_mobile_proofing.helpers import MobileMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(MobileMsg.no_phone.value, 'no_phone')
        self.assertEqual(MobileMsg.lookup_error.value, 'error_lookup_mobile_task')
        self.assertEqual(MobileMsg.verify_success.value, 'letter.verification_success')
        self.assertEqual(MobileMsg.no_match.value, 'nins.no-mobile-match')
