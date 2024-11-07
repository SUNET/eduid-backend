import unittest

from eduid.webapp.letter_proofing.helpers import LetterMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self) -> None:
        """"""
        self.assertEqual(LetterMsg.no_state.value, "letter.no_state_found")
        self.assertEqual(LetterMsg.already_sent.value, "letter.already-sent")
        self.assertEqual(LetterMsg.letter_expired.value, "letter.expired")
        self.assertEqual(LetterMsg.not_sent.value, "letter.not-sent")
        self.assertEqual(LetterMsg.address_not_found.value, "letter.no-address-found")
        self.assertEqual(LetterMsg.bad_address.value, "letter.bad-postal-address")
        self.assertEqual(LetterMsg.letter_sent.value, "letter.saved-unconfirmed")
        self.assertEqual(LetterMsg.wrong_code.value, "letter.wrong-code")
        self.assertEqual(LetterMsg.verify_success.value, "letter.verification_success")
