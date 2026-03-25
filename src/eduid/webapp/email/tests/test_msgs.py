from eduid.webapp.email.helpers import EmailMsg


class MessagesTests:
    def test_messages(self) -> None:
        """"""
        assert EmailMsg.missing.value == "emails.missing"
        assert EmailMsg.dupe.value == "emails.duplicated"
        assert EmailMsg.get_success.value == "emails.get-success"
        assert EmailMsg.throttled.value == "emails.throttled"
        assert EmailMsg.still_valid_code.value == "still-valid-code"
        assert EmailMsg.added_and_throttled.value == "emails.added-and-throttled"
        assert EmailMsg.saved.value == "emails.save-success"
        assert EmailMsg.unconfirmed_not_primary.value == "emails.unconfirmed_address_not_primary"
        assert EmailMsg.success_primary.value == "emails.primary-success"
        assert EmailMsg.invalid_code.value == "emails.code_invalid_or_expired"
        assert EmailMsg.unknown_email.value == "emails.unknown_email"
        assert EmailMsg.verify_success.value == "emails.verification-success"
        assert EmailMsg.cannot_remove_last.value == "emails.cannot_remove_unique"
        assert EmailMsg.cannot_remove_last_verified.value == "emails.cannot_remove_unique_verified"
        assert EmailMsg.removal_success.value == "emails.removal-success"
        assert EmailMsg.code_sent.value == "emails.code-sent"
