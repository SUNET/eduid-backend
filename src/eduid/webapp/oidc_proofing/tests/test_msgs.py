import unittest

from eduid.webapp.oidc_proofing.helpers import OIDCMsg


class MessagesTests(unittest.TestCase):
    def test_messages(self) -> None:
        """"""
        self.assertEqual(OIDCMsg.no_conn.value, "No connection to authorization endpoint")
