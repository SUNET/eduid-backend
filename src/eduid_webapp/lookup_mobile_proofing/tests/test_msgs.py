# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.lookup_mobile_proofing.helpers import MobileMsg


class MessagesTests(unittest.TestCase):

    def test_messages(self):
        """"""
        self.assertEqual(str(MobileMsg.no_phone.value), 'no_phone')
        self.assertEqual(str(MobileMsg.lookup_error.value), 'error_lookup_mobile_task')
        self.assertEqual(str(MobileMsg.navet_error.value), 'error_navet_task')
        self.assertEqual(str(MobileMsg.verify_success.value), 'letter.verification_success')
        self.assertEqual(str(MobileMsg.temp_error.value), 'Temporary technical problems')
        self.assertEqual(str(MobileMsg.no_match.value), 'nins.no-mobile-match')
