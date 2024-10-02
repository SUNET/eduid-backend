import unittest

from eduid.webapp.email.helpers import EmailMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self) -> None:
        """"""
        self.assertEqual(EmailMsg.missing.value, "emails.missing")
        self.assertEqual(EmailMsg.dupe.value, "emails.duplicated")
        self.assertEqual(EmailMsg.get_success.value, "emails.get-success")
        self.assertEqual(EmailMsg.throttled.value, "emails.throttled")
        self.assertEqual(EmailMsg.still_valid_code.value, "still-valid-code")
        self.assertEqual(EmailMsg.added_and_throttled.value, "emails.added-and-throttled")
        self.assertEqual(EmailMsg.saved.value, "emails.save-success")
        self.assertEqual(EmailMsg.unconfirmed_not_primary.value, "emails.unconfirmed_address_not_primary")
        self.assertEqual(EmailMsg.success_primary.value, "emails.primary-success")
        self.assertEqual(EmailMsg.invalid_code.value, "emails.code_invalid_or_expired")
        self.assertEqual(EmailMsg.unknown_email.value, "emails.unknown_email")
        self.assertEqual(EmailMsg.verify_success.value, "emails.verification-success")
        self.assertEqual(EmailMsg.cannot_remove_last.value, "emails.cannot_remove_unique")
        self.assertEqual(EmailMsg.cannot_remove_last_verified.value, "emails.cannot_remove_unique_verified")
        self.assertEqual(EmailMsg.removal_success.value, "emails.removal-success")
        self.assertEqual(EmailMsg.code_sent.value, "emails.code-sent")
