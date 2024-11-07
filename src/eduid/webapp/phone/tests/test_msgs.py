import unittest

from eduid.webapp.phone.helpers import PhoneMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self) -> None:
        """"""
        self.assertEqual(PhoneMsg.e164_error.value, "phone.e164_format")
        self.assertEqual(PhoneMsg.phone_invalid.value, "phone.phone_format")
        self.assertEqual(PhoneMsg.swedish_invalid.value, "phone.swedish_mobile_format")
        self.assertEqual(PhoneMsg.dupe.value, "phone.phone_duplicated")
        self.assertEqual(PhoneMsg.save_success.value, "phones.save-success")
        self.assertEqual(PhoneMsg.unconfirmed_primary.value, "phones.unconfirmed_number_not_primary")
        self.assertEqual(PhoneMsg.primary_success.value, "phones.primary-success")
        self.assertEqual(PhoneMsg.code_invalid.value, "phones.code_invalid_or_expired")
        self.assertEqual(PhoneMsg.unknown_phone.value, "phones.unknown_phone")
        self.assertEqual(PhoneMsg.verify_success.value, "phones.verification-success")
        self.assertEqual(PhoneMsg.removal_success.value, "phones.removal-success")
        self.assertEqual(PhoneMsg.still_valid_code.value, "still-valid-code")
        self.assertEqual(PhoneMsg.send_code_success.value, "phones.code-sent")
