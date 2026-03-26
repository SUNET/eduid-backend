from eduid.webapp.letter_proofing.helpers import LetterMsg


class MessagesTests:
    def test_messages(self) -> None:
        """"""
        assert LetterMsg.no_state.value == "letter.no_state_found"
        assert LetterMsg.already_sent.value == "letter.already-sent"
        assert LetterMsg.letter_expired.value == "letter.expired"
        assert LetterMsg.not_sent.value == "letter.not-sent"
        assert LetterMsg.address_not_found.value == "letter.no-address-found"
        assert LetterMsg.bad_address.value == "letter.bad-postal-address"
        assert LetterMsg.letter_sent.value == "letter.saved-unconfirmed"
        assert LetterMsg.wrong_code.value == "letter.wrong-code"
        assert LetterMsg.verify_success.value == "letter.verification_success"
