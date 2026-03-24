import unittest

from eduid.webapp.phone.helpers import PhoneMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self) -> None:
        """"""
        assert PhoneMsg.e164_error.value == "phone.e164_format"
        assert PhoneMsg.phone_invalid.value == "phone.phone_format"
        assert PhoneMsg.swedish_invalid.value == "phone.swedish_mobile_format"
        assert PhoneMsg.dupe.value == "phone.phone_duplicated"
        assert PhoneMsg.save_success.value == "phones.save-success"
        assert PhoneMsg.unconfirmed_primary.value == "phones.unconfirmed_number_not_primary"
        assert PhoneMsg.primary_success.value == "phones.primary-success"
        assert PhoneMsg.code_invalid.value == "phones.code_invalid_or_expired"
        assert PhoneMsg.unknown_phone.value == "phones.unknown_phone"
        assert PhoneMsg.verify_success.value == "phones.verification-success"
        assert PhoneMsg.removal_success.value == "phones.removal-success"
        assert PhoneMsg.still_valid_code.value == "still-valid-code"
        assert PhoneMsg.send_code_success.value == "phones.code-sent"
