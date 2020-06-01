# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.email.helpers import EmailMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(str(EmailMsg.missing.value), 'emails.missing')
        self.assertEqual(str(EmailMsg.dupe.value), 'emails.duplicated')
        self.assertEqual(str(EmailMsg.get_success.value), 'emails.get-success')
        self.assertEqual(str(EmailMsg.out_of_sync.value), 'user-out-of-sync')
        self.assertEqual(str(EmailMsg.throttled.value), 'emails.throttled')
        self.assertEqual(str(EmailMsg.still_valid_code.value), 'still-valid-code')
        self.assertEqual(str(EmailMsg.saved.value), 'emails.save-success')
        self.assertEqual(str(EmailMsg.unconfirmed_not_primary.value), 'emails.unconfirmed_address_not_primary')
        self.assertEqual(str(EmailMsg.success_primary.value), 'emails.primary-success')
        self.assertEqual(str(EmailMsg.invalid_code.value), 'emails.code_invalid_or_expired')
        self.assertEqual(str(EmailMsg.unknown_email.value), 'emails.unknown_email')
        self.assertEqual(str(EmailMsg.verify_success.value), 'emails.verification-success')
        self.assertEqual(str(EmailMsg.cannot_remove_last.value), 'emails.cannot_remove_unique')
        self.assertEqual(str(EmailMsg.cannot_remove_last_verified.value), 'emails.cannot_remove_unique_verified')
        self.assertEqual(str(EmailMsg.removal_success.value), 'emails.removal-success')
        self.assertEqual(str(EmailMsg.code_sent.value), 'emails.code-sent')
        self.assertEqual(str(EmailMsg.invalid_email.value), 'email needs to be formatted according to RFC2822')
