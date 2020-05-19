# -*- coding: utf-8 -*-

import unittest

from eduid_webapp.letter_proofing.helpers import LetterMsg


class MessagesTests(unittest.TestCase):

    def test_messages(self):
        """"""
        self.assertEqual(str(LetterMsg.no_state.value), 'letter.no_state_found')
        self.assertEqual(str(LetterMsg.already_sent.value), 'letter.already-sent')
        self.assertEqual(str(LetterMsg.letter_expired.value), 'letter.expired')
        self.assertEqual(str(LetterMsg.not_sent.value), 'letter.not-sent')
        self.assertEqual(str(LetterMsg.address_not_found.value), 'letter.no-address-found')
        self.assertEqual(str(LetterMsg.naver_error.value), 'error_navet_task')
        self.assertEqual(str(LetterMsg.bad_address.value), 'letter.bad-postal-address')
        self.assertEqual(str(LetterMsg.temp_error.value), 'Temporary technical problems')
        self.assertEqual(str(LetterMsg.letter_sent.value), 'letter.saved-unconfirmed')
        self.assertEqual(str(LetterMsg.wrong_code.value), 'letter.wrong-code')
        self.assertEqual(str(LetterMsg.verify_success.value), 'letter.verification_success')
