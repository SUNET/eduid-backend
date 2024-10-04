import unittest

from eduid.webapp.orcid.helpers import OrcidMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self) -> None:
        """"""
        self.assertEqual(OrcidMsg.already_connected.value, "orc.already_connected")
        self.assertEqual(OrcidMsg.authz_error.value, "orc.authorization_fail")
        self.assertEqual(OrcidMsg.no_state.value, "orc.unknown_state")
        self.assertEqual(OrcidMsg.unknown_nonce.value, "orc.unknown_nonce")
        self.assertEqual(OrcidMsg.sub_mismatch.value, "orc.sub_mismatch")
        self.assertEqual(OrcidMsg.authz_success.value, "orc.authorization_success")
