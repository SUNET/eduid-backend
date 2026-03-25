from eduid.webapp.orcid.helpers import OrcidMsg


class MessagesTests:
    def test_messages(self) -> None:
        """"""
        assert OrcidMsg.already_connected.value == "orc.already_connected"
        assert OrcidMsg.authz_error.value == "orc.authorization_fail"
        assert OrcidMsg.no_state.value == "orc.unknown_state"
        assert OrcidMsg.unknown_nonce.value == "orc.unknown_nonce"
        assert OrcidMsg.sub_mismatch.value == "orc.sub_mismatch"
        assert OrcidMsg.authz_success.value == "orc.authorization_success"
