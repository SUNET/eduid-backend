import unittest

from eduid.webapp.lookup_mobile_proofing.helpers import MobileMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self) -> None:
        """"""
        assert MobileMsg.no_phone.value == "no_phone"
        assert MobileMsg.lookup_error.value == "error_lookup_mobile_task"
        assert MobileMsg.verify_success.value == "letter.verification_success"
        assert MobileMsg.no_match.value == "nins.no-mobile-match"
