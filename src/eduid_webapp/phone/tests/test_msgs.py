# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.phone.helpers import PhoneMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(str(PhoneMsg.out_of_sync.value), 'user-out-of-sync')
        self.assertEqual(str(PhoneMsg.e164_error.value), "phone.e164_format")
        self.assertEqual(str(PhoneMsg.phone_invalid.value), "phone.phone_format")
        self.assertEqual(str(PhoneMsg.swedish_invalid.value), "phone.swedish_mobile_format")
        self.assertEqual(str(PhoneMsg.dupe.value), "phone.phone_duplicated")
        self.assertEqual(str(PhoneMsg.save_success.value), 'phones.save-success')
        self.assertEqual(str(PhoneMsg.unconfirmed_primary.value), 'phones.unconfirmed_number_not_primary')
        self.assertEqual(str(PhoneMsg.primary_success.value), 'phones.primary-success')
        self.assertEqual(str(PhoneMsg.code_invalid.value), 'phones.code_invalid_or_expired')
        self.assertEqual(str(PhoneMsg.unknown_phone.value), 'phones.unknown_phone')
        self.assertEqual(str(PhoneMsg.verify_success.value), 'phones.verification-success')
        self.assertEqual(str(PhoneMsg.removal_success.value), 'phones.removal-success')
        self.assertEqual(str(PhoneMsg.still_valid_code.value), 'still-valid-code')
        self.assertEqual(str(PhoneMsg.resend_success.value), 'phones.code-sent')
